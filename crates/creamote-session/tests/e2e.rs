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
use creamote_session::host::{self, Consent, ConsentPrompt, InputSink, Media, Policy};
use creamote_session::viewer::{self, Event, Options};
use creamote_session::{EndReason, SessionError};

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
    let (a, b) = tokio::io::duplex(1 << 20);
    let v_id = DeviceIdentity::generate();
    let h_id = DeviceIdentity::generate();
    let (v, h) = tokio::join!(
        SecureChannel::initiate(a, &v_id),
        SecureChannel::respond(b, &h_id)
    );
    let (htx, hrx) = h.unwrap().split();
    let host = tokio::spawn(host::serve(htx, hrx, policy, media(log)));
    let (vtx, vrx) = v.unwrap().split();
    let opts = Options {
        display_name: "Test".into(),
        ..Default::default()
    };
    let (handle, events) = viewer::start(vtx, vrx, opts);
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
