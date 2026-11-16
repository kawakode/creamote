//! Transfert de fichiers dans les deux sens.
//!
//! [`FileTransfers::spawn`] démarre une tâche qui gère tous les transferts de
//! la session. La boucle de session lui remet les messages reçus
//! ([`FilesHandle::deliver`]) et envoie au pair ceux qu'elle produit (canal
//! `out`). L'interface pilote les envois et répond aux propositions par le
//! [`FilesHandle`], et suit l'avancement par les [`TransferEvent`].
//!
//! Côté réception, le fichier est écrit dans `<nom>.creamote-part` puis
//! renommé une fois son empreinte BLAKE3 vérifiée ; un fichier existant n'est
//! jamais écrasé. Les chemins reçus sont validés par [`crate::paths`].

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use creamote_proto::session::v1::session_message::Kind;
use creamote_proto::session::v1::{
    FileAck, FileAnswer, FileCancel, FileChunk, FileEnd, FileOffer, FileResult, SessionMessage,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, watch};

use crate::{msg, paths};

/// Taille des morceaux (un message chiffré fait au plus 64 Kio).
pub const CHUNK_SIZE: usize = 48 * 1024;
/// Octets envoyés au-delà du dernier accusé de réception.
pub const WINDOW: u64 = 4 * 1024 * 1024;
/// Le destinataire accuse réception tous les `ACK_EVERY` octets.
const ACK_EVERY: u64 = 512 * 1024;
/// Délai de réponse à une proposition (l'utilisateur peut devoir accepter).
const ANSWER_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Délai sans accusé de réception avant d'abandonner.
const STALL_TIMEOUT: Duration = Duration::from_secs(60);
/// Intervalle minimal entre deux événements de progression.
const PROGRESS_EVERY: u64 = 1024 * 1024;
const PART_SUFFIX: &str = ".creamote-part";

pub type TransferId = u64;

/// Sens d'un transfert, vu de ce côté.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    Send,
    Receive,
}

/// Que faire des fichiers proposés par le pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptPolicy {
    /// Accepter (dossier de destination choisi d'avance).
    AcceptAll,
    /// Demander : [`TransferEvent::Offered`], puis [`FilesHandle::accept`]
    /// ou [`FilesHandle::reject`].
    Ask,
    /// Tout refuser (ex. host sans destinataire présent).
    RejectAll,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferEvent {
    /// Le pair propose un fichier (politique [`AcceptPolicy::Ask`]).
    Offered {
        id: TransferId,
        path: String,
        size: u64,
    },
    Progress {
        id: TransferId,
        direction: Direction,
        done: u64,
        total: u64,
    },
    Completed {
        id: TransferId,
        direction: Direction,
        /// Fichier local (source ou fichier reçu).
        path: PathBuf,
    },
    Failed {
        id: TransferId,
        direction: Direction,
        reason: String,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum TransferError {
    #[error("fichier local : {0}")]
    Io(#[from] std::io::Error),
    #[error("nom de fichier non représentable")]
    BadName,
    #[error("session de transfert terminée")]
    Closed,
}

enum Command {
    Send {
        path: PathBuf,
        name: String,
        reply: oneshot::Sender<Result<TransferId, TransferError>>,
    },
    Accept(TransferId),
    Reject(TransferId, String),
    Cancel(TransferId, Direction),
}

enum Input {
    Peer(SessionMessage),
    Command(Command),
    /// Fin d'un envoi (tâche terminée).
    SendDone(TransferId),
}

/// Pilotage des transferts d'une session (clonable).
///
/// La file d'entrée n'est pas bornée : [`Self::deliver`] ne bloque jamais la
/// boucle de session (sinon deux pairs qui s'envoient des fichiers en même
/// temps pourraient s'attendre mutuellement). Le volume en attente reste
/// borné par la fenêtre d'envoi de l'émetteur ([`WINDOW`]).
#[derive(Clone)]
pub struct FilesHandle {
    tx: mpsc::UnboundedSender<Input>,
}

impl FilesHandle {
    /// Remet un message de fichier reçu du pair (voir [`crate::route`]).
    pub fn deliver(&self, msg: SessionMessage) -> Result<(), TransferError> {
        self.tx
            .send(Input::Peer(msg))
            .map_err(|_| TransferError::Closed)
    }

    /// Propose un fichier au pair sous le nom relatif `name` (séparateur
    /// « / »).
    pub async fn send_file(
        &self,
        path: impl Into<PathBuf>,
        name: impl Into<String>,
    ) -> Result<TransferId, TransferError> {
        let (reply, rx) = oneshot::channel();
        self.command(Command::Send {
            path: path.into(),
            name: name.into(),
            reply,
        })
        .await?;
        rx.await.map_err(|_| TransferError::Closed)?
    }

    /// Envoie un fichier ou un dossier entier (chaque fichier est proposé
    /// séparément, chemins relatifs au parent de `path`).
    pub async fn send_path(&self, path: &Path) -> Result<Vec<TransferId>, TransferError> {
        let mut files = Vec::new();
        collect_files(path, &mut files).await?;
        let mut ids = Vec::new();
        for f in files {
            let name = paths::relative_name(path, &f).ok_or(TransferError::BadName)?;
            ids.push(self.send_file(f, name).await?);
        }
        Ok(ids)
    }

    pub async fn accept(&self, id: TransferId) -> Result<(), TransferError> {
        self.command(Command::Accept(id)).await
    }

    pub async fn reject(&self, id: TransferId, reason: &str) -> Result<(), TransferError> {
        self.command(Command::Reject(id, reason.to_owned())).await
    }

    pub async fn cancel(&self, id: TransferId, direction: Direction) -> Result<(), TransferError> {
        self.command(Command::Cancel(id, direction)).await
    }

    async fn command(&self, c: Command) -> Result<(), TransferError> {
        self.tx
            .send(Input::Command(c))
            .map_err(|_| TransferError::Closed)
    }
}

async fn collect_files(path: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    let meta = tokio::fs::symlink_metadata(path).await?;
    if meta.is_file() {
        out.push(path.to_owned());
    } else if meta.is_dir() {
        let mut entries = tokio::fs::read_dir(path).await?;
        let mut children = Vec::new();
        while let Some(e) = entries.next_entry().await? {
            children.push(e.path());
        }
        children.sort();
        for c in children {
            Box::pin(collect_files(&c, out)).await?;
        }
    }
    // Liens symboliques et fichiers spéciaux ignorés.
    Ok(())
}

/// Contrôle d'un envoi en cours, côté gestionnaire.
struct Outgoing {
    answer: Option<oneshot::Sender<FileAnswer>>,
    acked: watch::Sender<u64>,
    result: Option<oneshot::Sender<FileResult>>,
    cancel: watch::Sender<Option<String>>,
}

enum Incoming {
    Pending(FileOffer),
    Receiving(Box<Receiving>),
}

struct Receiving {
    file: tokio::fs::File,
    part: PathBuf,
    rel: PathBuf,
    size: u64,
    modified_unix_ms: i64,
    received: u64,
    last_ack: u64,
    last_progress: u64,
    hasher: blake3::Hasher,
}

pub struct FileTransfers {
    out: mpsc::Sender<SessionMessage>,
    events: mpsc::UnboundedSender<TransferEvent>,
    dest: PathBuf,
    policy: AcceptPolicy,
    next_id: TransferId,
    outgoing: HashMap<TransferId, Outgoing>,
    incoming: HashMap<TransferId, Incoming>,
    /// Faible : chaque tâche d'envoi en détient une copie forte, pour que le
    /// gestionnaire s'arrête une fois les FilesHandle et les envois finis.
    self_tx: mpsc::WeakUnboundedSender<Input>,
}

impl FileTransfers {
    /// Démarre le gestionnaire de transferts d'une session. `out` reçoit les
    /// messages à envoyer au pair ; les fichiers reçus sont écrits sous
    /// `dest`.
    pub fn spawn(
        out: mpsc::Sender<SessionMessage>,
        dest: PathBuf,
        policy: AcceptPolicy,
    ) -> (FilesHandle, mpsc::UnboundedReceiver<TransferEvent>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let (events, events_rx) = mpsc::unbounded_channel();
        let this = Self {
            out,
            events,
            dest,
            policy,
            next_id: 1,
            outgoing: HashMap::new(),
            incoming: HashMap::new(),
            self_tx: tx.downgrade(),
        };
        tokio::spawn(this.run(rx));
        (FilesHandle { tx }, events_rx)
    }

    async fn run(mut self, mut rx: mpsc::UnboundedReceiver<Input>) {
        // S'arrête quand plus aucun FilesHandle ni envoi n'existe.
        while let Some(input) = rx.recv().await {
            let r = match input {
                Input::Peer(m) => self.on_peer(m).await,
                Input::Command(c) => self.on_command(c).await,
                Input::SendDone(id) => {
                    self.outgoing.remove(&id);
                    Ok(())
                }
            };
            if r.is_err() {
                // Le pair n'écoute plus (canal `out` fermé).
                break;
            }
        }
        self.abort_incoming().await;
    }

    async fn send(&self, kind: Kind) -> Result<(), TransferError> {
        self.out
            .send(msg(kind))
            .await
            .map_err(|_| TransferError::Closed)
    }

    fn event(&self, e: TransferEvent) {
        let _ = self.events.send(e);
    }

    async fn on_command(&mut self, c: Command) -> Result<(), TransferError> {
        match c {
            Command::Send { path, name, reply } => {
                let r = self.start_send(path, name).await;
                let closed = matches!(r, Err(TransferError::Closed));
                let _ = reply.send(r);
                if closed {
                    return Err(TransferError::Closed);
                }
            }
            Command::Accept(id) => {
                if let Some(Incoming::Pending(offer)) = self.incoming.remove(&id) {
                    self.start_receive(offer).await?;
                }
            }
            Command::Reject(id, reason) => {
                if let Some(Incoming::Pending(_)) = self.incoming.remove(&id) {
                    self.answer(id, false, &reason).await?;
                }
            }
            Command::Cancel(id, Direction::Send) => {
                if let Some(o) = self.outgoing.remove(&id) {
                    let _ = o.cancel.send(Some("annulé".into()));
                    self.send(Kind::FileCancel(FileCancel {
                        transfer_id: id,
                        reason: "annulé par l'émetteur".into(),
                        by_sender: true,
                    }))
                    .await?;
                    self.event(failed(id, Direction::Send, "annulé"));
                }
            }
            Command::Cancel(id, Direction::Receive) => {
                if let Some(state) = self.incoming.remove(&id) {
                    discard(state).await;
                    self.send(Kind::FileCancel(FileCancel {
                        transfer_id: id,
                        reason: "annulé par le destinataire".into(),
                        by_sender: false,
                    }))
                    .await?;
                    self.event(failed(id, Direction::Receive, "annulé"));
                }
            }
        }
        Ok(())
    }

    async fn start_send(
        &mut self,
        path: PathBuf,
        name: String,
    ) -> Result<TransferId, TransferError> {
        paths::sanitize(&name).map_err(|_| TransferError::BadName)?;
        let meta = tokio::fs::metadata(&path).await?;
        if !meta.is_file() {
            return Err(std::io::Error::other("pas un fichier").into());
        }
        let id = self.next_id;
        self.next_id += 1;
        let modified_unix_ms = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_millis() as i64);
        let (answer_tx, answer_rx) = oneshot::channel();
        let (acked_tx, acked_rx) = watch::channel(0);
        let (result_tx, result_rx) = oneshot::channel();
        let (cancel_tx, cancel_rx) = watch::channel(None);
        self.outgoing.insert(
            id,
            Outgoing {
                answer: Some(answer_tx),
                acked: acked_tx,
                result: Some(result_tx),
                cancel: cancel_tx,
            },
        );
        self.send(Kind::FileOffer(FileOffer {
            transfer_id: id,
            path: name,
            size: meta.len(),
            modified_unix_ms,
        }))
        .await?;
        let task = SendTask {
            id,
            path,
            size: meta.len(),
            out: self.out.clone(),
            events: self.events.clone(),
            answer: answer_rx,
            acked: acked_rx,
            result: result_rx,
            cancel: cancel_rx,
        };
        let done = self.self_tx.upgrade().ok_or(TransferError::Closed)?;
        tokio::spawn(async move {
            task.run().await;
            let _ = done.send(Input::SendDone(id));
        });
        Ok(id)
    }

    async fn on_peer(&mut self, m: SessionMessage) -> Result<(), TransferError> {
        match m.kind {
            // Messages sur nos envois.
            Some(Kind::FileAnswer(a)) => {
                if let Some(tx) = self
                    .outgoing
                    .get_mut(&a.transfer_id)
                    .and_then(|o| o.answer.take())
                {
                    let _ = tx.send(a);
                }
            }
            Some(Kind::FileAck(a)) => {
                if let Some(o) = self.outgoing.get(&a.transfer_id) {
                    o.acked.send_if_modified(|v| {
                        let newer = a.received > *v;
                        if newer {
                            *v = a.received;
                        }
                        newer
                    });
                }
            }
            Some(Kind::FileResult(r)) => {
                if let Some(tx) = self
                    .outgoing
                    .get_mut(&r.transfer_id)
                    .and_then(|o| o.result.take())
                {
                    let _ = tx.send(r);
                }
            }
            Some(Kind::FileCancel(c)) if !c.by_sender => {
                if let Some(o) = self.outgoing.remove(&c.transfer_id) {
                    let _ = o
                        .cancel
                        .send(Some(format!("annulé par le pair : {}", c.reason)));
                }
            }
            // Messages sur les fichiers que le pair nous envoie.
            Some(Kind::FileOffer(o)) => self.on_offer(o).await?,
            Some(Kind::FileChunk(c)) => self.on_chunk(c).await?,
            Some(Kind::FileEnd(e)) => self.on_end(e).await?,
            Some(Kind::FileCancel(c)) => {
                if let Some(state) = self.incoming.remove(&c.transfer_id) {
                    discard(state).await;
                    self.event(failed(
                        c.transfer_id,
                        Direction::Receive,
                        &format!("annulé par le pair : {}", c.reason),
                    ));
                }
            }
            _ => {}
        }
        Ok(())
    }

    async fn answer(
        &self,
        id: TransferId,
        accepted: bool,
        reason: &str,
    ) -> Result<(), TransferError> {
        self.send(Kind::FileAnswer(FileAnswer {
            transfer_id: id,
            accepted,
            reason: reason.to_owned(),
        }))
        .await
    }

    async fn on_offer(&mut self, offer: FileOffer) -> Result<(), TransferError> {
        let id = offer.transfer_id;
        if self.incoming.contains_key(&id) {
            return self.answer(id, false, "identifiant déjà utilisé").await;
        }
        if let Err(e) = paths::sanitize(&offer.path) {
            return self.answer(id, false, &e.to_string()).await;
        }
        match self.policy {
            AcceptPolicy::RejectAll => self.answer(id, false, "transferts refusés").await,
            AcceptPolicy::AcceptAll => self.start_receive(offer).await,
            AcceptPolicy::Ask => {
                self.event(TransferEvent::Offered {
                    id,
                    path: offer.path.clone(),
                    size: offer.size,
                });
                self.incoming.insert(id, Incoming::Pending(offer));
                Ok(())
            }
        }
    }

    async fn start_receive(&mut self, offer: FileOffer) -> Result<(), TransferError> {
        let id = offer.transfer_id;
        let opened = async {
            let rel =
                paths::sanitize(&offer.path).map_err(|e| std::io::Error::other(e.to_string()))?;
            let target = self.dest.join(&rel);
            if let Some(parent) = target.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            let part = part_path(&paths::unique(&self.dest, &rel));
            let file = tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&part)
                .await?;
            std::io::Result::Ok((rel, part, file))
        }
        .await;
        match opened {
            Ok((rel, part, file)) => {
                self.incoming.insert(
                    id,
                    Incoming::Receiving(Box::new(Receiving {
                        file,
                        part,
                        rel,
                        size: offer.size,
                        modified_unix_ms: offer.modified_unix_ms,
                        received: 0,
                        last_ack: 0,
                        last_progress: 0,
                        hasher: blake3::Hasher::new(),
                    })),
                );
                self.answer(id, true, "").await
            }
            Err(e) => {
                self.event(failed(id, Direction::Receive, &e.to_string()));
                self.answer(id, false, "écriture impossible chez le destinataire")
                    .await
            }
        }
    }

    async fn on_chunk(&mut self, c: FileChunk) -> Result<(), TransferError> {
        let id = c.transfer_id;
        let Some(Incoming::Receiving(r)) = self.incoming.get_mut(&id) else {
            return Ok(());
        };
        let len = c.data.len() as u64;
        let problem = if c.offset != r.received {
            Some("morceau hors séquence".to_owned())
        } else if r.received + len > r.size {
            Some("plus de données qu'annoncé".to_owned())
        } else if let Err(e) = r.file.write_all(&c.data).await {
            Some(format!("écriture : {e}"))
        } else {
            None
        };
        if let Some(reason) = problem {
            return self.fail_incoming(id, &reason).await;
        }
        r.hasher.update(&c.data);
        r.received += len;
        let (received, size) = (r.received, r.size);
        let ack = received - r.last_ack >= ACK_EVERY || received == size;
        if ack {
            r.last_ack = received;
        }
        let progress = received - r.last_progress >= PROGRESS_EVERY;
        if progress {
            r.last_progress = received;
        }
        if ack {
            self.send(Kind::FileAck(FileAck {
                transfer_id: id,
                received,
            }))
            .await?;
        }
        if progress {
            self.event(TransferEvent::Progress {
                id,
                direction: Direction::Receive,
                done: received,
                total: size,
            });
        }
        Ok(())
    }

    async fn on_end(&mut self, e: FileEnd) -> Result<(), TransferError> {
        let id = e.transfer_id;
        let Some(Incoming::Receiving(mut r)) = self.incoming.remove(&id) else {
            return Ok(());
        };
        let finished = async {
            if r.received != r.size {
                return Err("fichier incomplet".to_owned());
            }
            if r.hasher.finalize().as_bytes().as_slice() != e.blake3.as_slice() {
                return Err("empreinte BLAKE3 différente".to_owned());
            }
            r.file.flush().await.map_err(|e| e.to_string())?;
            r.file.sync_all().await.map_err(|e| e.to_string())?;
            // Le nom choisi à l'ouverture a pu être pris entre-temps.
            let target = paths::unique(&self.dest, &r.rel);
            tokio::fs::rename(&r.part, &target)
                .await
                .map_err(|e| e.to_string())?;
            Ok(target)
        }
        .await;
        match finished {
            Ok(path) => {
                if r.modified_unix_ms > 0 {
                    set_mtime(&path, r.modified_unix_ms).await;
                }
                self.send(Kind::FileResult(FileResult {
                    transfer_id: id,
                    ok: true,
                    error: String::new(),
                }))
                .await?;
                self.event(TransferEvent::Completed {
                    id,
                    direction: Direction::Receive,
                    path,
                });
            }
            Err(reason) => {
                discard(Incoming::Receiving(r)).await;
                self.send(Kind::FileResult(FileResult {
                    transfer_id: id,
                    ok: false,
                    error: reason.clone(),
                }))
                .await?;
                self.event(failed(id, Direction::Receive, &reason));
            }
        }
        Ok(())
    }

    async fn fail_incoming(&mut self, id: TransferId, reason: &str) -> Result<(), TransferError> {
        if let Some(state) = self.incoming.remove(&id) {
            discard(state).await;
        }
        self.event(failed(id, Direction::Receive, reason));
        self.send(Kind::FileCancel(FileCancel {
            transfer_id: id,
            reason: reason.to_owned(),
            by_sender: false,
        }))
        .await
    }

    /// Fin de session : supprime les fichiers partiels.
    async fn abort_incoming(&mut self) {
        for (id, state) in std::mem::take(&mut self.incoming) {
            if matches!(state, Incoming::Receiving(_)) {
                self.event(failed(id, Direction::Receive, "session terminée"));
            }
            discard(state).await;
        }
    }
}

fn failed(id: TransferId, direction: Direction, reason: &str) -> TransferEvent {
    TransferEvent::Failed {
        id,
        direction,
        reason: reason.to_owned(),
    }
}

fn part_path(target: &Path) -> PathBuf {
    let mut name = target.file_name().unwrap_or_default().to_os_string();
    name.push(PART_SUFFIX);
    target.with_file_name(name)
}

async fn discard(state: Incoming) {
    if let Incoming::Receiving(r) = state {
        drop(r.file);
        let _ = tokio::fs::remove_file(&r.part).await;
    }
}

async fn set_mtime(path: &Path, unix_ms: i64) {
    let path = path.to_owned();
    let t = UNIX_EPOCH + Duration::from_millis(unix_ms as u64);
    let _ = tokio::task::spawn_blocking(move || {
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .and_then(|f| f.set_modified(t))
    })
    .await;
}

/// Tâche d'envoi d'un fichier.
struct SendTask {
    id: TransferId,
    path: PathBuf,
    size: u64,
    out: mpsc::Sender<SessionMessage>,
    events: mpsc::UnboundedSender<TransferEvent>,
    answer: oneshot::Receiver<FileAnswer>,
    acked: watch::Receiver<u64>,
    result: oneshot::Receiver<FileResult>,
    cancel: watch::Receiver<Option<String>>,
}

impl SendTask {
    async fn run(mut self) {
        let mut cancel = self.cancel.clone();
        let outcome = tokio::select! {
            r = self.transfer() => r,
            c = cancel.wait_for(Option::is_some) => {
                Err(c.map(|v| v.clone().unwrap_or_default()).unwrap_or_default())
            }
        };
        let event = match outcome {
            Ok(()) => TransferEvent::Completed {
                id: self.id,
                direction: Direction::Send,
                path: self.path.clone(),
            },
            Err(reason) => failed(self.id, Direction::Send, &reason),
        };
        let _ = self.events.send(event);
    }

    async fn send(&self, kind: Kind) -> Result<(), String> {
        self.out
            .send(msg(kind))
            .await
            .map_err(|_| "session terminée".to_owned())
    }

    async fn transfer(&mut self) -> Result<(), String> {
        let answer = tokio::time::timeout(ANSWER_TIMEOUT, &mut self.answer)
            .await
            .map_err(|_| "pas de réponse du pair".to_owned())?
            .map_err(|_| "session terminée".to_owned())?;
        if !answer.accepted {
            return Err(format!("refusé : {}", answer.reason));
        }
        let mut file = tokio::fs::File::open(&self.path)
            .await
            .map_err(|e| format!("lecture : {e}"))?;
        let mut hasher = blake3::Hasher::new();
        let mut buf = vec![0u8; CHUNK_SIZE];
        let mut offset = 0u64;
        let mut last_progress = 0u64;
        while offset < self.size {
            // Fenêtre : on attend les accusés de réception du pair.
            let window_open = |acked: &u64| offset - *acked < WINDOW;
            tokio::time::timeout(STALL_TIMEOUT, self.acked.wait_for(window_open))
                .await
                .map_err(|_| "le pair ne répond plus".to_owned())?
                .map_err(|_| "session terminée".to_owned())?;
            let want = ((self.size - offset) as usize).min(CHUNK_SIZE);
            let n = file
                .read(&mut buf[..want])
                .await
                .map_err(|e| format!("lecture : {e}"))?;
            if n == 0 {
                return Err("fichier raccourci pendant l'envoi".into());
            }
            hasher.update(&buf[..n]);
            self.send(Kind::FileChunk(FileChunk {
                transfer_id: self.id,
                offset,
                data: buf[..n].to_vec(),
            }))
            .await?;
            offset += n as u64;
            if offset - last_progress >= PROGRESS_EVERY {
                last_progress = offset;
                let _ = self.events.send(TransferEvent::Progress {
                    id: self.id,
                    direction: Direction::Send,
                    done: offset,
                    total: self.size,
                });
            }
        }
        self.send(Kind::FileEnd(FileEnd {
            transfer_id: self.id,
            blake3: hasher.finalize().as_bytes().to_vec(),
        }))
        .await?;
        let result = tokio::time::timeout(STALL_TIMEOUT, &mut self.result)
            .await
            .map_err(|_| "pas de confirmation du pair".to_owned())?
            .map_err(|_| "session terminée".to_owned())?;
        if result.ok {
            Ok(())
        } else {
            Err(format!("rejeté par le pair : {}", result.error))
        }
    }
}
