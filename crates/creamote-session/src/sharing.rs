//! Presse-papier partagé et transfert de fichiers (M3) dans une session.
//!
//! Désactivés par défaut ([`Sharing::default`]). Chaque côté choisit ce qu'il
//! offre ; le host n'accorde la permission que s'il sait l'honorer, et les
//! messages d'une fonction non accordée sont ignorés.

use std::path::PathBuf;

use creamote_proto::permissions::Permissions;
use creamote_proto::session::v1::SessionMessage;
use creamote_proto::session::v1::session_message::Kind;
use creamote_transfer::clipboard::{ClipboardBackend, ClipboardSync, POLL_INTERVAL};
use creamote_transfer::files::{AcceptPolicy, FileTransfers, FilesHandle, TransferEvent};
use creamote_transfer::{Route, route};
use tokio::sync::mpsc;

/// Fonctions de partage offertes par ce côté de la session.
#[derive(Default)]
pub struct Sharing {
    /// Presse-papier à synchroniser (`NativeClipboard` en général).
    pub clipboard: Option<Box<dyn ClipboardBackend>>,
    pub files: Option<FilesConfig>,
}

/// Réception et envoi de fichiers.
pub struct FilesConfig {
    /// Dossier où sont écrits les fichiers reçus.
    pub dest: PathBuf,
    pub policy: AcceptPolicy,
    /// Avancement des transferts (sinon simplement journalisé).
    pub events: Option<mpsc::UnboundedSender<TransferEvent>>,
}

impl Sharing {
    /// Permissions que ce côté sait honorer.
    pub fn permissions(&self) -> Permissions {
        let mut p = Permissions::NONE;
        if self.clipboard.is_some() {
            p = p | Permissions::CLIPBOARD;
        }
        if self.files.is_some() {
            p = p | Permissions::FILE_TRANSFER;
        }
        p
    }
}

/// Partage en cours dans une session acceptée.
pub(crate) struct Active {
    clipboard: Option<ClipboardSync>,
    files: Option<FilesHandle>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Active {
    /// Démarre les fonctions accordées ; `out` reçoit les messages à envoyer
    /// au pair.
    pub(crate) fn start(sharing: Sharing, granted: Permissions, out: mpsc::Sender<Kind>) -> Self {
        let mut tasks = Vec::new();
        let clipboard = match sharing.clipboard {
            Some(backend) if granted.contains(Permissions::CLIPBOARD) => {
                let sync = ClipboardSync::new(backend);
                let mut copies = sync.watch(POLL_INTERVAL);
                let out = out.clone();
                tasks.push(tokio::spawn(async move {
                    while let Some(msgs) = copies.recv().await {
                        if forward(&out, msgs).await.is_err() {
                            break;
                        }
                    }
                }));
                Some(sync)
            }
            _ => None,
        };
        let files = match sharing.files {
            Some(cfg) if granted.contains(Permissions::FILE_TRANSFER) => {
                let (msg_tx, mut msg_rx) = mpsc::channel::<SessionMessage>(16);
                let (handle, mut events) = FileTransfers::spawn(msg_tx, cfg.dest, cfg.policy);
                tasks.push(tokio::spawn(async move {
                    while let Some(m) = msg_rx.recv().await {
                        if forward(&out, vec![m]).await.is_err() {
                            break;
                        }
                    }
                }));
                let sink = cfg.events;
                tasks.push(tokio::spawn(async move {
                    while let Some(ev) = events.recv().await {
                        tracing::info!(?ev, "transfert de fichier");
                        if let Some(s) = &sink {
                            let _ = s.send(ev);
                        }
                    }
                }));
                Some(handle)
            }
            _ => None,
        };
        Self {
            clipboard,
            files,
            tasks,
        }
    }

    /// Pilotage des transferts, si accordés.
    pub(crate) fn files(&self) -> Option<FilesHandle> {
        self.files.clone()
    }

    /// Traite un message reçu s'il relève du partage ; sinon le rend.
    pub(crate) async fn handle(&mut self, kind: Kind) -> Option<Kind> {
        match route(SessionMessage { kind: Some(kind) }) {
            Route::Clipboard(chunk) => {
                if let Some(sync) = &mut self.clipboard {
                    if let Err(e) = sync.receive(chunk).await {
                        tracing::debug!("presse-papier reçu ignoré : {e}");
                    }
                }
                None
            }
            Route::File(m) => {
                if let Some(f) = &self.files {
                    let _ = f.deliver(m);
                }
                None
            }
            Route::Other(m) => m.kind,
        }
    }
}

impl Drop for Active {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

async fn forward(out: &mpsc::Sender<Kind>, msgs: Vec<SessionMessage>) -> Result<(), ()> {
    for m in msgs {
        if let Some(k) = m.kind {
            out.send(k).await.map_err(|_| ())?;
        }
    }
    Ok(())
}
