//! Deux gestionnaires de transferts reliés par un « fil » en mémoire qui
//! encode chaque message comme dans la session réelle.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use creamote_crypto::noise::MAX_PLAINTEXT_LEN;
use creamote_proto::session::v1::session_message::Kind;
use creamote_proto::session::v1::{FileOffer, SessionMessage};
use creamote_transfer::files::{
    AcceptPolicy, Direction, FileTransfers, FilesHandle, TransferEvent,
};
use creamote_transfer::{Route, route};
use prost::Message;
use tokio::sync::mpsc;

fn temp_dir(label: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "creamote-transfer-{}-{}-{label}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn pseudo_random(len: usize, seed: u8) -> Vec<u8> {
    let mut x = u32::from(seed) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

/// Fil : encode/décode chaque message (taille vérifiée), puis le remet au
/// gestionnaire d'en face. `tamper` peut modifier les messages au passage.
fn wire(
    mut from: mpsc::Receiver<SessionMessage>,
    to: FilesHandle,
    tamper: fn(&mut SessionMessage),
) {
    tokio::spawn(async move {
        while let Some(mut m) = from.recv().await {
            tamper(&mut m);
            let bytes = m.encode_to_vec();
            assert!(bytes.len() <= MAX_PLAINTEXT_LEN, "message trop grand");
            let m = SessionMessage::decode(bytes.as_slice()).unwrap();
            match route(m) {
                Route::File(m) => {
                    if to.deliver(m).is_err() {
                        break;
                    }
                }
                other => panic!("message inattendu : {other:?}"),
            }
        }
    });
}

struct Side {
    files: FilesHandle,
    events: mpsc::UnboundedReceiver<TransferEvent>,
    dir: PathBuf,
}

fn pair(
    policy_a: AcceptPolicy,
    policy_b: AcceptPolicy,
    tamper: fn(&mut SessionMessage),
) -> (Side, Side) {
    let (a_out, a_rx) = mpsc::channel(16);
    let (b_out, b_rx) = mpsc::channel(16);
    let (dir_a, dir_b) = (temp_dir("a"), temp_dir("b"));
    let (a, a_events) = FileTransfers::spawn(a_out, dir_a.clone(), policy_a);
    let (b, b_events) = FileTransfers::spawn(b_out, dir_b.clone(), policy_b);
    wire(a_rx, b.clone(), tamper);
    wire(b_rx, a.clone(), |_| {});
    (
        Side {
            files: a,
            events: a_events,
            dir: dir_a,
        },
        Side {
            files: b,
            events: b_events,
            dir: dir_b,
        },
    )
}

/// Attend le prochain événement final (terminé ou échoué) d'un sens donné.
async fn outcome(
    events: &mut mpsc::UnboundedReceiver<TransferEvent>,
    dir: Direction,
) -> TransferEvent {
    loop {
        let e = tokio::time::timeout(Duration::from_secs(20), events.recv())
            .await
            .expect("délai dépassé")
            .expect("canal fermé");
        match &e {
            TransferEvent::Completed { direction, .. }
            | TransferEvent::Failed { direction, .. }
                if *direction == dir =>
            {
                return e;
            }
            _ => {}
        }
    }
}

fn no_part_files(dir: &Path) -> bool {
    walk(dir)
        .iter()
        .all(|p| !p.to_string_lossy().ends_with(".creamote-part"))
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

#[tokio::test]
async fn files_cross_in_both_directions_at_once() {
    let (mut a, mut b) = pair(AcceptPolicy::AcceptAll, AcceptPolicy::AcceptAll, |_| {});
    let big = pseudo_random(5 * 1024 * 1024 + 123, 1);
    let src = a.dir.join("source");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("gros.bin"), &big).unwrap();
    let from_b = pseudo_random(70_000, 2);
    std::fs::write(b.dir.join("retour.txt"), &from_b).unwrap();

    a.files
        .send_file(src.join("gros.bin"), "gros.bin")
        .await
        .unwrap();
    b.files
        .send_file(b.dir.join("retour.txt"), "retour.txt")
        .await
        .unwrap();

    match outcome(&mut b.events, Direction::Receive).await {
        TransferEvent::Completed { path, .. } => {
            assert_eq!(path, b.dir.join("gros.bin"));
            assert_eq!(std::fs::read(&path).unwrap(), big);
        }
        e => panic!("{e:?}"),
    }
    // Côté A : fin de l'envoi et fin de la réception, dans un ordre
    // quelconque.
    let (mut sent, mut received) = (false, false);
    while !(sent && received) {
        match a.events.recv().await.unwrap() {
            TransferEvent::Completed {
                direction: Direction::Send,
                ..
            } => sent = true,
            TransferEvent::Completed {
                direction: Direction::Receive,
                path,
                ..
            } => {
                assert_eq!(std::fs::read(path).unwrap(), from_b);
                received = true;
            }
            TransferEvent::Failed { reason, .. } => panic!("{reason}"),
            _ => {}
        }
    }
    assert!(no_part_files(&a.dir) && no_part_files(&b.dir));
}

#[tokio::test]
async fn folders_keep_their_structure_and_never_overwrite() {
    let (a, mut b) = pair(AcceptPolicy::AcceptAll, AcceptPolicy::AcceptAll, |_| {});
    let root = a.dir.join("projet");
    std::fs::create_dir_all(root.join("src/sous")).unwrap();
    std::fs::write(root.join("lisez-moi.md"), b"1").unwrap();
    std::fs::write(root.join("src/main.rs"), b"2").unwrap();
    std::fs::write(root.join("src/sous/vide.txt"), b"").unwrap();
    // Déjà présent chez le destinataire : ne doit pas être écrasé.
    std::fs::create_dir_all(b.dir.join("projet")).unwrap();
    std::fs::write(b.dir.join("projet/lisez-moi.md"), b"ancien").unwrap();

    let ids = a.files.send_path(&root).await.unwrap();
    assert_eq!(ids.len(), 3);
    for _ in 0..3 {
        assert!(matches!(
            outcome(&mut b.events, Direction::Receive).await,
            TransferEvent::Completed { .. }
        ));
    }
    let got = |p: &str| std::fs::read(b.dir.join(p)).unwrap();
    assert_eq!(got("projet/lisez-moi.md"), b"ancien");
    assert_eq!(got("projet/lisez-moi (1).md"), b"1");
    assert_eq!(got("projet/src/main.rs"), b"2");
    assert_eq!(got("projet/src/sous/vide.txt"), b"");
}

#[tokio::test]
async fn offers_can_be_accepted_or_rejected() {
    let (mut a, mut b) = pair(AcceptPolicy::AcceptAll, AcceptPolicy::Ask, |_| {});
    std::fs::write(a.dir.join("oui.txt"), b"oui").unwrap();
    std::fs::write(a.dir.join("non.txt"), b"non").unwrap();
    let yes = a
        .files
        .send_file(a.dir.join("oui.txt"), "oui.txt")
        .await
        .unwrap();
    let no = a
        .files
        .send_file(a.dir.join("non.txt"), "non.txt")
        .await
        .unwrap();

    for _ in 0..2 {
        match b.events.recv().await.unwrap() {
            TransferEvent::Offered { id, path, size } => {
                assert_eq!(size, 3);
                if id == yes {
                    assert_eq!(path, "oui.txt");
                    b.files.accept(id).await.unwrap();
                } else {
                    assert_eq!(id, no);
                    b.files.reject(id, "pas maintenant").await.unwrap();
                }
            }
            e => panic!("{e:?}"),
        }
    }
    let mut results = Vec::new();
    for _ in 0..2 {
        results.push(outcome(&mut a.events, Direction::Send).await);
    }
    assert!(results.iter().any(|e| matches!(e,
        TransferEvent::Completed { id, .. } if *id == yes)));
    assert!(results.iter().any(|e| matches!(e,
        TransferEvent::Failed { id, reason, .. } if *id == no && reason.contains("pas maintenant"))));
    assert_eq!(std::fs::read(b.dir.join("oui.txt")).unwrap(), b"oui");
    assert!(!b.dir.join("non.txt").exists());
}

#[tokio::test]
async fn dangerous_paths_are_refused() {
    let (out, mut out_rx) = mpsc::channel(4);
    let dir = temp_dir("evil");
    let (files, _events) = FileTransfers::spawn(out, dir.join("dest"), AcceptPolicy::AcceptAll);
    for (id, path) in [(1, "../evasion.txt"), (2, "C:/Windows/x"), (3, "a/../../b")] {
        files
            .deliver(SessionMessage {
                kind: Some(Kind::FileOffer(FileOffer {
                    transfer_id: id,
                    path: path.into(),
                    size: 1,
                    modified_unix_ms: 0,
                })),
            })
            .unwrap();
        match out_rx.recv().await.unwrap().kind {
            Some(Kind::FileAnswer(a)) => assert!(!a.accepted && a.transfer_id == id),
            other => panic!("{other:?}"),
        }
    }
    assert!(!dir.join("evasion.txt").exists());
}

#[tokio::test]
async fn corrupted_data_is_detected_and_discarded() {
    fn flip(m: &mut SessionMessage) {
        if let Some(Kind::FileChunk(c)) = &mut m.kind {
            if c.offset == 0 {
                c.data[0] ^= 1;
            }
        }
    }
    let (mut a, mut b) = pair(AcceptPolicy::AcceptAll, AcceptPolicy::AcceptAll, flip);
    std::fs::write(a.dir.join("f.bin"), pseudo_random(100_000, 3)).unwrap();
    a.files
        .send_file(a.dir.join("f.bin"), "f.bin")
        .await
        .unwrap();

    assert!(matches!(
        outcome(&mut b.events, Direction::Receive).await,
        TransferEvent::Failed { reason, .. } if reason.contains("BLAKE3")
    ));
    assert!(matches!(
        outcome(&mut a.events, Direction::Send).await,
        TransferEvent::Failed { .. }
    ));
    assert!(walk(&b.dir).is_empty());
}

#[tokio::test]
async fn receiver_can_cancel_mid_transfer() {
    let (mut a, mut b) = pair(AcceptPolicy::AcceptAll, AcceptPolicy::AcceptAll, |_| {});
    std::fs::write(a.dir.join("long.bin"), pseudo_random(40 * 1024 * 1024, 4)).unwrap();
    a.files
        .send_file(a.dir.join("long.bin"), "long.bin")
        .await
        .unwrap();
    let id = loop {
        if let Some(TransferEvent::Progress {
            id,
            direction: Direction::Receive,
            ..
        }) = b.events.recv().await
        {
            break id;
        }
    };
    b.files.cancel(id, Direction::Receive).await.unwrap();
    assert!(matches!(
        outcome(&mut a.events, Direction::Send).await,
        TransferEvent::Failed { reason, .. } if reason.contains("annulé")
    ));
    assert!(walk(&b.dir).is_empty());
}

#[tokio::test]
async fn manager_stops_when_handles_are_dropped() {
    let (out, mut out_rx) = mpsc::channel(4);
    let (files, mut events) = FileTransfers::spawn(out, temp_dir("stop"), AcceptPolicy::AcceptAll);
    drop(files);
    // Le gestionnaire s'arrête : ses canaux se ferment.
    assert!(
        tokio::time::timeout(Duration::from_secs(2), events.recv())
            .await
            .unwrap()
            .is_none()
    );
    assert!(out_rx.recv().await.is_none());
}
