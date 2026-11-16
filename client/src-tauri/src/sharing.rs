//! Presse-papier partagé et transfert de fichiers dans le client.
//!
//! Le cœur (`creamote-transfer`, via `creamote-session`) fait le travail ;
//! ce module l'adapte à l'interface :
//! - [`GatedClipboard`] : presse-papier natif que l'utilisateur peut
//!   suspendre pendant la session (bouton de la barre d'outils) ;
//! - [`send_paths`] : envoi de fichiers ou de dossiers choisis par
//!   l'utilisateur (boîte de dialogue ou glisser-déposer) ;
//! - [`event_json`] : avancement des transferts pour l'interface.
//!
//! Les chemins envoyés viennent toujours d'une action native de
//! l'utilisateur (dialogue, dépôt sur la fenêtre), jamais de la WebView.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use creamote_session::creamote_transfer::clipboard::{
    ClipboardBackend, ClipboardContent, ClipboardError,
};
use creamote_session::creamote_transfer::files::{Direction, FilesHandle, TransferEvent};
use creamote_session::creamote_transfer::paths;
use serde_json::{Value, json};

/// Presse-papier dont la synchronisation peut être suspendue : désactivé, il
/// paraît vide (rien n'est envoyé au pair) et ignore les copies reçues.
pub struct GatedClipboard {
    inner: Box<dyn ClipboardBackend>,
    enabled: Arc<AtomicBool>,
}

impl GatedClipboard {
    pub fn new(inner: Box<dyn ClipboardBackend>, enabled: Arc<AtomicBool>) -> Self {
        Self { inner, enabled }
    }

    fn on(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }
}

impl ClipboardBackend for GatedClipboard {
    fn read(&mut self) -> Result<ClipboardContent, ClipboardError> {
        if self.on() {
            self.inner.read()
        } else {
            Ok(ClipboardContent::default())
        }
    }

    fn write(&mut self, content: &ClipboardContent) -> Result<(), ClipboardError> {
        if self.on() {
            self.inner.write(content)
        } else {
            Ok(())
        }
    }

    fn change_count(&mut self) -> Option<u64> {
        // Suspendu : pas de compteur, pour que `read` (vide) soit appelé et
        // que le contenu présent soit relu à la reprise.
        if self.on() {
            self.inner.change_count()
        } else {
            None
        }
    }
}

/// Fichier à proposer : chemin local, nom relatif envoyé, taille.
#[derive(Debug, PartialEq, Eq)]
pub struct Outgoing {
    pub path: PathBuf,
    pub name: String,
    pub size: u64,
}

/// Fichiers réguliers sous `root` (fichier ou dossier), dans l'ordre des
/// noms, avec leur chemin relatif au parent de `root`. Liens symboliques et
/// fichiers spéciaux ignorés, comme dans `creamote-transfer`.
pub async fn collect(root: &Path) -> std::io::Result<Vec<Outgoing>> {
    let mut stack = vec![root.to_owned()];
    let mut out = Vec::new();
    while let Some(p) = stack.pop() {
        let meta = tokio::fs::symlink_metadata(&p).await?;
        if meta.is_file() {
            let name = paths::relative_name(root, &p)
                .ok_or_else(|| std::io::Error::other("nom de fichier non représentable"))?;
            out.push(Outgoing {
                path: p,
                name,
                size: meta.len(),
            });
        } else if meta.is_dir() {
            let mut entries = tokio::fs::read_dir(&p).await?;
            let mut children = Vec::new();
            while let Some(e) = entries.next_entry().await? {
                children.push(e.path());
            }
            // Pile : ordre inverse pour traiter les noms dans l'ordre.
            children.sort_by(|a, b| b.cmp(a));
            stack.extend(children);
        }
    }
    Ok(out)
}

/// Propose au pair chaque fichier sous `roots` ; `emit` reçoit un événement
/// `queued` par fichier proposé, `failed` sinon.
pub async fn send_paths(files: &FilesHandle, roots: Vec<PathBuf>, emit: impl Fn(Value)) {
    for root in roots {
        let list = match collect(&root).await {
            Ok(l) => l,
            Err(e) => {
                emit(local_failure(&root, &e.to_string()));
                continue;
            }
        };
        if list.is_empty() {
            emit(local_failure(&root, "aucun fichier à envoyer"));
        }
        for f in list {
            match files.send_file(&f.path, &f.name).await {
                Ok(id) => emit(json!({
                    "type": "transfer",
                    "event": "queued",
                    "id": id,
                    "direction": "send",
                    "name": f.name,
                    "total": f.size,
                })),
                Err(e) => emit(local_failure(&f.path, &e.to_string())),
            }
        }
    }
}

/// Échec avant toute proposition (fichier illisible…) : pas d'identifiant.
fn local_failure(path: &Path, reason: &str) -> Value {
    json!({
        "type": "transfer",
        "event": "error",
        "name": path.file_name().map(|n| n.to_string_lossy().into_owned()),
        "reason": reason,
    })
}

pub fn direction_name(d: Direction) -> &'static str {
    match d {
        Direction::Send => "send",
        Direction::Receive => "receive",
    }
}

pub fn parse_direction(s: &str) -> Option<Direction> {
    match s {
        "send" => Some(Direction::Send),
        "receive" => Some(Direction::Receive),
        _ => None,
    }
}

/// Événement de transfert pour l'interface. Les identifiants des envois et
/// des réceptions sont indépendants : l'interface les distingue par le sens.
pub fn event_json(ev: &TransferEvent) -> Value {
    match ev {
        TransferEvent::Offered { id, path, size } => json!({
            "type": "transfer",
            "event": "offered",
            "id": id,
            "direction": "receive",
            "name": path,
            "total": size,
        }),
        TransferEvent::Progress {
            id,
            direction,
            done,
            total,
        } => json!({
            "type": "transfer",
            "event": "progress",
            "id": id,
            "direction": direction_name(*direction),
            "done": done,
            "total": total,
        }),
        TransferEvent::Completed {
            id,
            direction,
            path,
        } => json!({
            "type": "transfer",
            "event": "completed",
            "id": id,
            "direction": direction_name(*direction),
            "path": path.to_string_lossy(),
        }),
        TransferEvent::Failed {
            id,
            direction,
            reason,
        } => json!({
            "type": "transfer",
            "event": "failed",
            "id": id,
            "direction": direction_name(*direction),
            "reason": reason,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use creamote_session::creamote_transfer::clipboard::MemoryClipboard;

    #[test]
    fn gate_blocks_both_ways() {
        let mem = MemoryClipboard::default();
        let on = Arc::new(AtomicBool::new(false));
        let mut gate = GatedClipboard::new(Box::new(mem.clone()), on.clone());
        mem.0.lock().unwrap().text = Some("secret".into());
        assert!(gate.read().unwrap().is_empty());
        let incoming = ClipboardContent {
            text: Some("du pair".into()),
            ..Default::default()
        };
        gate.write(&incoming).unwrap();
        assert_eq!(mem.0.lock().unwrap().text.as_deref(), Some("secret"));

        on.store(true, Ordering::Relaxed);
        assert_eq!(gate.read().unwrap().text.as_deref(), Some("secret"));
        gate.write(&incoming).unwrap();
        assert_eq!(mem.0.lock().unwrap().text.as_deref(), Some("du pair"));
    }

    #[tokio::test]
    async fn collect_walks_folders_in_order() {
        let base = std::env::temp_dir().join(format!("creamote-client-{}", std::process::id()));
        let root = base.join("dossier");
        std::fs::create_dir_all(root.join("sous")).unwrap();
        std::fs::write(root.join("b.txt"), b"bb").unwrap();
        std::fs::write(root.join("a.txt"), b"a").unwrap();
        std::fs::write(root.join("sous/c.txt"), b"ccc").unwrap();

        let names: Vec<_> = collect(&root)
            .await
            .unwrap()
            .into_iter()
            .map(|f| (f.name, f.size))
            .collect();
        assert_eq!(
            names,
            [
                ("dossier/a.txt".to_owned(), 1),
                ("dossier/b.txt".to_owned(), 2),
                ("dossier/sous/c.txt".to_owned(), 3)
            ]
        );
        let single = collect(&root.join("a.txt")).await.unwrap();
        assert_eq!(single[0].name, "a.txt");
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn events_keep_direction() {
        let ev = TransferEvent::Progress {
            id: 3,
            direction: Direction::Receive,
            done: 10,
            total: 20,
        };
        let v = event_json(&ev);
        assert_eq!(v["direction"], "receive");
        assert_eq!(v["done"], 10);
        assert_eq!(parse_direction("send"), Some(Direction::Send));
        assert_eq!(parse_direction("x"), None);
    }
}
