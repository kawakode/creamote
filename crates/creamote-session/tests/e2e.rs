//! Session complète host ↔ viewer sur un canal Noise en mémoire, avec un
//! écran synthétique, l'encodeur logiciel et un puits d'entrées espion.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use creamote_capture::{Capturer, DisplayInfo, Frame};
use creamote_codec::{H264Decoder, Preference};
use creamote_crypto::DeviceIdentity;
use creamote_input::Pointer;
use creamote_net::secure::SecureChannel;
use creamote_proto::permissions::Permissions;
use creamote_proto::session::v1::PointerEvent;
use creamote_session::creamote_transfer::clipboard::{ClipboardContent, MemoryClipboard};
use creamote_session::creamote_transfer::files::{AcceptPolicy, Direction, TransferEvent};
use creamote_session::host::{self, Consent, ConsentPrompt, InputSink, Media, Policy};
use creamote_session::viewer::{self, Event, Options};
use creamote_session::{EndReason, FilesConfig, SessionError, Sharing};

fn display() -> DisplayInfo {
    DisplayInfo {
        id: 7,
        name: "synthétique".into(),
        x: 0,
        y: 0,
        width: 320,
        height: 180,
        scale: 1.0,
        primary: true,
    }
}

/// Écran dont la couleur change à chaque image.
struct Synthetic(u8);

impl Capturer for Synthetic {
    fn display(&self) -> &DisplayInfo {
        static D: std::sync::OnceLock<DisplayInfo> = std::sync::OnceLock::new();
        D.get_or_init(display)
    }
    fn next_frame(&mut self, _: Duration) -> creamote_capture::Result<Option<Frame>> {
        std::thread::sleep(Duration::from_millis(5));
        self.0 = self.0.wrapping_add(16);
        Ok(Some(Frame::solid(320, 180, [self.0, 100, 200, 255])))
    }
}

type Log = Arc<Mutex<Vec<String>>>;

struct Spy(Log);

impl InputSink for Spy {
    fn key(&mut self, hid: u32, pressed: bool) {
        self.0
            .lock()
            .unwrap()
            .push(format!("key {hid:#x} {pressed}"));
    }
    fn pointer(&mut self, p: &Pointer) {
        self.0
            .lock()
            .unwrap()
            .push(format!("pointer {} {} {}", p.x, p.y, p.buttons));
    }
}

fn media(log: Log) -> Media {
    Media {
        displays: Arc::new(|| Ok(vec![display()])),
        capturer: Arc::new(|_| Ok(Box::new(Synthetic(0)) as Box<dyn Capturer>)),
        injector: Arc::new(move |_| Ok(Box::new(Spy(log.clone())) as Box<dyn InputSink>)),
        encoder: Preference::Software,
        encoded: None,
        max_bitrate_bps: 0,
    }
}

async fn session(
    policy: Policy,
    log: Log,
) -> (
    viewer::Handle,
    tokio::sync::mpsc::Receiver<Event>,
    tokio::task::JoinHandle<creamote_session::Result<host::Summary>>,
) {
    session_sharing(policy, log, Sharing::default(), Sharing::default()).await
}

async fn session_sharing(
    policy: Policy,
    log: Log,
    host_sharing: Sharing,
    viewer_sharing: Sharing,
) -> (
    viewer::Handle,
    tokio::sync::mpsc::Receiver<Event>,
    tokio::task::JoinHandle<creamote_session::Result<host::Summary>>,
) {
    let (a, b) = tokio::io::duplex(1 << 20);
    let v_id = DeviceIdentity::generate();
    let h_id = DeviceIdentity::generate();
    let (v, h) = tokio::join!(
        SecureChannel::initiate(a, &v_id),
        SecureChannel::respond(b, &h_id)
    );
    let (htx, hrx) = h.unwrap().split();
    let host = tokio::spawn(host::serve_with(htx, hrx, policy, media(log), host_sharing));
    let (vtx, vrx) = v.unwrap().split();
    let opts = Options {
        display_name: "Test".into(),
        ..Default::default()
    };
    let (handle, events) = viewer::start_with(vtx, vrx, opts, viewer_sharing);
    (handle, events, host)
}

async fn next(events: &mut tokio::sync::mpsc::Receiver<Event>) -> Event {
    tokio::time::timeout(Duration::from_secs(20), events.recv())
        .await
        .expect("événement attendu")
        .expect("canal fermé")
}

fn prompt(answer: Consent, seen: Arc<Mutex<Option<host::ConsentRequest>>>) -> ConsentPrompt {
    Arc::new(move |req| {
        *seen.lock().unwrap() = Some(req);
        answer
    })
}

#[tokio::test]
async fn video_flows_and_control_is_injected() {
    let log = Log::default();
    let seen = Arc::default();
    let policy = Policy {
        allowed: Permissions::ALL,
        consent: Some(prompt(Consent::Control, Arc::clone(&seen))),
        user_email: Some("tech@example.org".into()),
    };
    let (handle, mut events, host) = session(policy, log.clone()).await;

    let Event::Accepted { granted, displays } = next(&mut events).await else {
        panic!("Accepted attendu");
    };
    assert_eq!(granted, Permissions::VIEW | Permissions::CONTROL);
    assert_eq!(displays[0].id, 7);
    let req = seen.lock().unwrap().clone().unwrap();
    assert_eq!(req.viewer_name, "Test");
    assert_eq!(req.user_email.as_deref(), Some("tech@example.org"));
    assert_eq!(req.verification_code.len(), 6);

    let Event::Video(cfg) = next(&mut events).await else {
        panic!("VideoConfig attendu");
    };
    assert_eq!((cfg.width, cfg.height, cfg.display_id), (320, 180, 7));
    assert!(cfg.encoder.contains("openh264"));

    // Plusieurs images décodables ; la première est une image clé. Sans
    // accusé de réception, le host s'arrête à MAX_FRAMES_IN_FLIGHT.
    let mut dec = H264Decoder::new().unwrap();
    let mut decoded = 0;
    let start = Instant::now();
    while decoded < 10 {
        match next(&mut events).await {
            Event::Frame(f) => {
                if decoded == 0 {
                    assert!(f.keyframe);
                }
                let img = dec.decode(&f.data).unwrap().unwrap();
                assert_eq!((img.width, img.height), (320, 180));
                handle.ack(f.frame_id).await.unwrap();
                decoded += 1;
            }
            // Débit adaptatif : nouveau VideoConfig informatif possible.
            Event::Video(_) => {}
            other => panic!("image attendue : {other:?}"),
        }
    }
    assert!(start.elapsed() < Duration::from_secs(15));

    handle.key(0x04, true).await.unwrap();
    handle
        .pointer(PointerEvent {
            display_id: 7,
            x: 0.5,
            y: 0.25,
            buttons: 1,
            ..Default::default()
        })
        .await
        .unwrap();
    handle.request_keyframe().await.unwrap();
    // Une image clé finit par arriver après la demande.
    loop {
        if let Event::Frame(f) = next(&mut events).await {
            handle.ack(f.frame_id).await.unwrap();
            if f.keyframe {
                break;
            }
        }
    }
    handle.close().await;
    let summary = host.await.unwrap().unwrap();
    assert_eq!(summary.granted, Permissions::VIEW | Permissions::CONTROL);
    assert_eq!(*log.lock().unwrap(), ["key 0x4 true", "pointer 0.5 0.25 1"]);
}

#[tokio::test]
async fn view_only_consent_drops_input() {
    let log = Log::default();
    let policy = Policy {
        allowed: Permissions::ALL,
        consent: Some(prompt(Consent::ViewOnly, Arc::default())),
        user_email: None,
    };
    let (handle, mut events, host) = session(policy, log.clone()).await;
    let Event::Accepted { granted, .. } = next(&mut events).await else {
        panic!("Accepted attendu");
    };
    assert_eq!(granted, Permissions::VIEW);
    // Attendre que le flux soit ouvert pour que l'entrée ait une cible.
    while !matches!(next(&mut events).await, Event::Frame(_)) {}
    handle.key(0x04, true).await.unwrap();
    handle.close().await;
    host.await.unwrap().unwrap();
    assert!(log.lock().unwrap().is_empty());
}

#[tokio::test]
async fn declined_consent_ends_session() {
    let policy = Policy {
        allowed: Permissions::ALL,
        consent: Some(prompt(Consent::Deny, Arc::default())),
        user_email: None,
    };
    let (_handle, mut events, host) = session(policy, Log::default()).await;
    let Event::Ended { reason, .. } = next(&mut events).await else {
        panic!("Ended attendu");
    };
    assert_eq!(reason, EndReason::Declined);
    assert!(matches!(
        host.await.unwrap(),
        Err(SessionError::Ended {
            reason: EndReason::Declined,
            ..
        })
    ));
}

#[tokio::test]
async fn ticket_without_view_is_refused_and_unattended_skips_consent() {
    let policy = Policy {
        allowed: Permissions::CONTROL,
        consent: None,
        user_email: None,
    };
    let (_h, mut events, _host) = session(policy, Log::default()).await;
    let Event::Ended { reason, .. } = next(&mut events).await else {
        panic!("Ended attendu");
    };
    assert_eq!(reason, EndReason::Forbidden);

    let policy = Policy {
        allowed: Permissions::VIEW,
        consent: None,
        user_email: None,
    };
    let (handle, mut events, host) = session(policy, Log::default()).await;
    let Event::Accepted { granted, .. } = next(&mut events).await else {
        panic!("Accepted attendu");
    };
    assert_eq!(granted, Permissions::VIEW);
    handle.close().await;
    host.await.unwrap().unwrap();
}

fn temp_dir(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("creamote-session-{}-{label}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn text(t: &str) -> ClipboardContent {
    ClipboardContent {
        text: Some(t.into()),
        ..Default::default()
    }
}

async fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    let start = Instant::now();
    while !cond() {
        assert!(start.elapsed() < Duration::from_secs(10), "{what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn clipboard_and_files_are_shared_when_granted() {
    let host_clip = MemoryClipboard::default();
    let viewer_clip = MemoryClipboard::default();
    let host_dir = temp_dir("host");
    let viewer_dir = temp_dir("viewer");
    let (host_ev_tx, mut host_events) = tokio::sync::mpsc::unbounded_channel();
    let host_sharing = Sharing {
        clipboard: Some(Box::new(host_clip.clone())),
        files: Some(FilesConfig {
            dest: host_dir.clone(),
            policy: AcceptPolicy::AcceptAll,
            events: Some(host_ev_tx),
        }),
    };
    let viewer_sharing = Sharing {
        clipboard: Some(Box::new(viewer_clip.clone())),
        files: Some(FilesConfig {
            dest: viewer_dir.clone(),
            policy: AcceptPolicy::AcceptAll,
            events: None,
        }),
    };
    let policy = Policy {
        allowed: Permissions::ALL,
        consent: Some(prompt(Consent::Control, Arc::default())),
        user_email: None,
    };
    let (handle, mut events, host) =
        session_sharing(policy, Log::default(), host_sharing, viewer_sharing).await;

    let Event::Accepted { granted, .. } = next(&mut events).await else {
        panic!("Accepted attendu");
    };
    assert_eq!(
        granted,
        Permissions::VIEW
            | Permissions::CONTROL
            | Permissions::CLIPBOARD
            | Permissions::FILE_TRANSFER
    );
    let files = loop {
        match next(&mut events).await {
            Event::Files(f) => break f,
            Event::Frame(f) => handle.ack(f.frame_id).await.unwrap(),
            _ => {}
        }
    };
    // Laisse les deux surveillances relever le presse-papier initial.
    tokio::time::sleep(Duration::from_millis(700)).await;

    // Copie chez le viewer → presse-papier du host, et inversement.
    *viewer_clip.0.lock().unwrap() = text("du viewer");
    wait_for("copie viewer → host", || {
        *host_clip.0.lock().unwrap() == text("du viewer")
    })
    .await;
    *host_clip.0.lock().unwrap() = text("du host");
    wait_for("copie host → viewer", || {
        *viewer_clip.0.lock().unwrap() == text("du host")
    })
    .await;

    // Fichier du viewer vers le host.
    let src = viewer_dir.join("rapport.txt");
    std::fs::write(&src, b"contenu").unwrap();
    files.send_file(&src, "rapport.txt").await.unwrap();
    let received = loop {
        let ev = tokio::time::timeout(Duration::from_secs(10), host_events.recv())
            .await
            .unwrap()
            .unwrap();
        if let TransferEvent::Completed {
            direction: Direction::Receive,
            path,
            ..
        } = ev
        {
            break path;
        }
    };
    assert_eq!(std::fs::read(received).unwrap(), b"contenu");

    handle.close().await;
    host.await.unwrap().unwrap();
}

#[tokio::test]
async fn view_only_consent_disables_sharing() {
    let host_clip = MemoryClipboard::default();
    let viewer_clip = MemoryClipboard::default();
    let policy = Policy {
        allowed: Permissions::ALL,
        consent: Some(prompt(Consent::ViewOnly, Arc::default())),
        user_email: None,
    };
    let host_sharing = Sharing {
        clipboard: Some(Box::new(host_clip.clone())),
        files: None,
    };
    let viewer_sharing = Sharing {
        clipboard: Some(Box::new(viewer_clip.clone())),
        files: None,
    };
    let (handle, mut events, host) =
        session_sharing(policy, Log::default(), host_sharing, viewer_sharing).await;
    let Event::Accepted { granted, .. } = next(&mut events).await else {
        panic!("Accepted attendu");
    };
    assert_eq!(granted, Permissions::VIEW);
    tokio::time::sleep(Duration::from_millis(700)).await;
    *viewer_clip.0.lock().unwrap() = text("secret");
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(*host_clip.0.lock().unwrap(), ClipboardContent::default());
    handle.close().await;
    host.await.unwrap().unwrap();
}

/// Second écran qui « disparaît » après quelques images.
struct Unplugged(u32);

impl Capturer for Unplugged {
    fn display(&self) -> &DisplayInfo {
        static D: std::sync::OnceLock<DisplayInfo> = std::sync::OnceLock::new();
        D.get_or_init(|| DisplayInfo {
            id: 8,
            name: "second".into(),
            x: 320,
            primary: false,
            ..display()
        })
    }
    fn next_frame(&mut self, _: Duration) -> creamote_capture::Result<Option<Frame>> {
        std::thread::sleep(Duration::from_millis(5));
        self.0 += 1;
        if self.0 > 5 {
            return Err(creamote_capture::CaptureError::Backend(
                "écran débranché".into(),
            ));
        }
        Ok(Some(Frame::solid(320, 180, [0, 0, 0, 255])))
    }
}

#[tokio::test]
async fn display_changes_are_announced_and_capture_falls_back_to_primary() {
    let second = DisplayInfo {
        id: 8,
        name: "second".into(),
        x: 320,
        primary: false,
        ..display()
    };
    let screens = Arc::new(Mutex::new(vec![display(), second]));
    let media = {
        let screens = screens.clone();
        Media {
            displays: Arc::new(move || Ok(screens.lock().unwrap().clone())),
            capturer: Arc::new(|id| {
                Ok(match id {
                    Some(8) => Box::new(Unplugged(0)) as Box<dyn Capturer>,
                    _ => Box::new(Synthetic(0)),
                })
            }),
            injector: Arc::new(|_| Ok(Box::new(Spy(Log::default())) as Box<dyn InputSink>)),
            encoder: Preference::Software,
            encoded: None,
            max_bitrate_bps: 0,
        }
    };
    let (a, b) = tokio::io::duplex(1 << 20);
    let (v_id, h_id) = (DeviceIdentity::generate(), DeviceIdentity::generate());
    let (v, h) = tokio::join!(
        SecureChannel::initiate(a, &v_id),
        SecureChannel::respond(b, &h_id)
    );
    let (htx, hrx) = h.unwrap().split();
    let policy = Policy {
        allowed: Permissions::ALL,
        consent: None,
        user_email: None,
    };
    let host = tokio::spawn(host::serve(htx, hrx, policy, media));
    let (vtx, vrx) = v.unwrap().split();
    let (handle, mut events) = viewer::start(vtx, vrx, Options::default());

    let Event::Accepted { displays, .. } = next(&mut events).await else {
        panic!("Accepted attendu");
    };
    assert_eq!(displays.len(), 2);
    handle.select_display(8, 30, 0).await.unwrap();

    // Le flux passe sur l'écran 8, puis revient sur l'écran principal
    // quand la capture échoue ; la liste des écrans est renvoyée quand
    // l'écran disparaît de la configuration.
    let mut seen_second = false;
    let mut back_to_primary = false;
    let mut announced = false;
    let start = Instant::now();
    while !(back_to_primary && announced) {
        assert!(start.elapsed() < Duration::from_secs(15), "délai dépassé");
        match next(&mut events).await {
            Event::Video(c) if c.display_id == 8 => {
                seen_second = true;
                screens.lock().unwrap().truncate(1);
            }
            Event::Video(c) if seen_second && c.display_id == 7 => back_to_primary = true,
            Event::Displays(d) => {
                assert_eq!(d.len(), 1);
                announced = true;
            }
            Event::Frame(f) => handle.ack(f.frame_id).await.unwrap(),
            Event::Ended { reason, message } => panic!("fin inattendue : {reason:?} {message}"),
            _ => {}
        }
    }
    handle.close().await;
    host.await.unwrap().unwrap();
}

/// Source déjà encodée (comme MediaProjection + MediaCodec sur Android) :
/// images factices, rotation après quelques images.
struct FakeEncoded {
    count: u64,
    keyframe_requests: Arc<Mutex<u32>>,
    bitrate: u32,
}

impl host::EncodedSource for FakeEncoded {
    fn display(&self) -> DisplayInfo {
        display()
    }
    fn name(&self) -> String {
        "MediaCodec factice".into()
    }
    fn size(&self) -> (u32, u32) {
        if self.count > 5 {
            (180, 320)
        } else {
            (320, 180)
        }
    }
    fn bitrate(&self) -> u32 {
        self.bitrate
    }
    fn next(&mut self, _: Duration) -> Result<Option<creamote_codec::EncodedFrame>, String> {
        std::thread::sleep(Duration::from_millis(5));
        self.count += 1;
        let keyframe =
            std::mem::take(&mut *self.keyframe_requests.lock().unwrap()) > 0 || self.count == 6;
        Ok(Some(creamote_codec::EncodedFrame {
            data: vec![self.count as u8; 100],
            keyframe,
            captured_at: Instant::now(),
        }))
    }
    fn request_keyframe(&mut self) {
        *self.keyframe_requests.lock().unwrap() += 1;
    }
    fn set_bitrate(&mut self, bps: u32) {
        self.bitrate = bps;
    }
}

#[tokio::test]
async fn encoded_source_streams_with_flow_control_and_resizes() {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let media = {
        let requests = requests.clone();
        Media::encoded(
            Arc::new(|| Ok(vec![display()])),
            Arc::new(move |r: host::SourceRequest| {
                requests.lock().unwrap().push(r);
                Ok(Box::new(FakeEncoded {
                    count: 0,
                    keyframe_requests: Arc::default(),
                    bitrate: 2_000_000,
                }) as Box<dyn host::EncodedSource>)
            }),
            Arc::new(|_| Ok(Box::new(Spy(Log::default())) as Box<dyn InputSink>)),
        )
    };
    let (a, b) = tokio::io::duplex(1 << 20);
    let (v_id, h_id) = (DeviceIdentity::generate(), DeviceIdentity::generate());
    let (v, h) = tokio::join!(
        SecureChannel::initiate(a, &v_id),
        SecureChannel::respond(b, &h_id)
    );
    let policy = Policy {
        allowed: Permissions::ALL,
        consent: None,
        user_email: None,
    };
    let (htx, hrx) = h.unwrap().split();
    let host = tokio::spawn(host::serve(htx, hrx, policy, media));
    let (vtx, vrx) = v.unwrap().split();
    let (handle, mut events) = viewer::start(vtx, vrx, Options::default());

    assert!(matches!(next(&mut events).await, Event::Accepted { .. }));
    let Event::Video(cfg) = next(&mut events).await else {
        panic!("VideoConfig attendu");
    };
    assert_eq!((cfg.width, cfg.height), (320, 180));
    assert_eq!(cfg.encoder, "MediaCodec factice");
    assert_eq!(cfg.target_bitrate_bps, 2_000_000);

    // La première image est une image clé (demandée à l'ouverture). Sans
    // accusé, le host n'envoie pas plus de MAX_FRAMES_IN_FLIGHT images.
    let mut frames = Vec::new();
    while frames.len() < 3 {
        if let Event::Frame(f) = next(&mut events).await {
            frames.push(f);
        }
    }
    assert!(frames[0].keyframe);
    assert!(
        tokio::time::timeout(Duration::from_millis(300), events.recv())
            .await
            .is_err(),
        "image envoyée au-delà de la fenêtre"
    );
    for f in &frames {
        handle.ack(f.frame_id).await.unwrap();
    }

    // Rotation : nouveau VideoConfig avant l'image clé suivante.
    let mut rotated = false;
    loop {
        match next(&mut events).await {
            Event::Video(c) if (c.width, c.height) == (180, 320) => rotated = true,
            Event::Frame(f) => {
                handle.ack(f.frame_id).await.unwrap();
                if rotated {
                    assert!(f.keyframe);
                    break;
                }
            }
            _ => {}
        }
    }
    let r = requests.lock().unwrap()[0];
    assert_eq!((r.display_id, r.fps, r.bitrate_bps), (Some(7), 30, 0));
    handle.close().await;
    host.await.unwrap().unwrap();
}
