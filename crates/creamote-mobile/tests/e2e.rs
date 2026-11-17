//! API de l'app Android de bout en bout : serveur réel, host et viewer de
//! `creamote-mobile` sur la machine locale, l'app étant simulée par des
//! rappels Rust (comme le feront les objets Kotlin).

use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use creamote_mobile::{
    ConnectRequest, ConsentAnswer, ConsentRequest, Display, HostConfig, HostDelegate, HostService,
    HostStatus, Identity, MobileError, ServerConfig, StreamInfo, StreamRequest, VideoConfig,
    VideoFrame, ViewerListener, connect, start_host,
};
use creamote_server::{Config, Policy, Server};

fn temp_dir(label: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "creamote-mobile-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// App host simulée : un « encodeur » qui pousse une image toutes les
/// 10 ms tant que le flux est démarré.
#[derive(Default)]
struct FakeApp {
    service: OnceLock<Arc<HostService>>,
    streaming: Arc<Mutex<bool>>,
    keyframe: Arc<Mutex<bool>>,
    log: Mutex<Vec<String>>,
    consent: Mutex<Option<ConsentRequest>>,
    status: Mutex<Option<Sender<HostStatus>>>,
}

impl HostDelegate for FakeApp {
    fn screen(&self) -> Display {
        Display {
            id: 0,
            name: "Écran intégré".into(),
            width: 360,
            height: 640,
            primary: true,
        }
    }
    fn consent(&self, request: ConsentRequest) -> ConsentAnswer {
        *self.consent.lock().unwrap() = Some(request);
        ConsentAnswer::Control
    }
    fn start_stream(&self, request: StreamRequest) -> Result<StreamInfo, MobileError> {
        assert_eq!(request.fps, 30);
        *self.streaming.lock().unwrap() = true;
        let service = self.service.get().unwrap().clone();
        let (streaming, keyframe) = (self.streaming.clone(), self.keyframe.clone());
        std::thread::spawn(move || {
            let mut n = 0u8;
            while *streaming.lock().unwrap() {
                let key = std::mem::take(&mut *keyframe.lock().unwrap());
                n = n.wrapping_add(1);
                service.push_frame(vec![n; 200], key, 360, 640);
                std::thread::sleep(Duration::from_millis(10));
            }
        });
        Ok(StreamInfo {
            encoder: "MediaCodec simulé".into(),
            bitrate_bps: 1_500_000,
        })
    }
    fn stop_stream(&self) {
        *self.streaming.lock().unwrap() = false;
        self.log.lock().unwrap().push("stop".into());
    }
    fn request_keyframe(&self) {
        *self.keyframe.lock().unwrap() = true;
    }
    fn set_bitrate(&self, _bps: u32) {}
    fn key(&self, hid: u32, android_keycode: Option<i32>, pressed: bool) {
        self.log
            .lock()
            .unwrap()
            .push(format!("key {hid:#x} {android_keycode:?} {pressed}"));
    }
    fn pointer(&self, x: f32, y: f32, buttons: u32, _: f32, _: f32) {
        self.log
            .lock()
            .unwrap()
            .push(format!("pointer {x} {y} {buttons}"));
    }
    fn release_all(&self) {
        self.log.lock().unwrap().push("release".into());
    }
    fn on_status(&self, status: HostStatus) {
        if let Some(tx) = &*self.status.lock().unwrap() {
            let _ = tx.send(status);
        }
    }
}

enum Ev {
    Accepted(Vec<String>),
    Video(VideoConfig),
    Frame(VideoFrame),
    Ended,
}

struct Listener(Mutex<Sender<Ev>>);

impl ViewerListener for Listener {
    fn on_accepted(&self, granted: Vec<String>, _displays: Vec<Display>) {
        let _ = self.0.lock().unwrap().send(Ev::Accepted(granted));
    }
    fn on_video_config(&self, config: VideoConfig) {
        let _ = self.0.lock().unwrap().send(Ev::Video(config));
    }
    fn on_displays(&self, _displays: Vec<Display>) {}
    fn on_frame(&self, frame: VideoFrame) {
        let _ = self.0.lock().unwrap().send(Ev::Frame(frame));
    }
    fn on_ended(&self, _reason: String, _message: String) {
        let _ = self.0.lock().unwrap().send(Ev::Ended);
    }
}

fn next<T>(rx: &Receiver<T>) -> T {
    rx.recv_timeout(Duration::from_secs(20))
        .expect("événement attendu")
}

#[test]
fn android_host_and_viewer_over_a_real_server() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt
        .block_on(Server::start(Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            data_dir: None,
            relay_addr: None,
            policy: Policy::private(),
            database_url: None,
            api_listen: None,
            trust_forwarded_for: false,
            oidc: None,
            public_url: None,
        }))
        .unwrap();
    let server_config = ServerConfig {
        address: server.local_addr().unwrap().to_string(),
        pin: server.pin().to_string(),
    };
    let dir = temp_dir("e2e");

    // Host.
    let host_id =
        Identity::load_or_create(dir.join("host.identity").display().to_string()).unwrap();
    let app = Arc::new(FakeApp::default());
    let (status_tx, status_rx) = channel();
    *app.status.lock().unwrap() = Some(status_tx);
    let service = start_host(
        host_id.clone(),
        HostConfig {
            server: Some(server_config.clone()),
            enrollment_path: dir.join("host.enrollment").display().to_string(),
            enroll_token: None,
            name: String::new(),
            relay_only: false,
            files_dir: None,
        },
        app.clone(),
        None,
    )
    .unwrap();
    app.service.set(service.clone()).ok().unwrap();
    assert_eq!(service.device_id(), host_id.device_id());
    assert!(service.enrollment().is_none());
    assert!(matches!(next(&status_rx), HostStatus::Online { .. }));

    // Viewer.
    let viewer_id =
        Identity::load_or_create(dir.join("viewer.identity").display().to_string()).unwrap();
    let (ev_tx, ev_rx) = channel();
    let session = connect(
        viewer_id.clone(),
        ConnectRequest {
            server: server_config.clone(),
            target: host_id.device_id(),
            api_url: None,
            api_token: None,
            view_only: false,
            display_name: "Pixel de test".into(),
        },
        Arc::new(Listener(Mutex::new(ev_tx))),
        None,
    )
    .unwrap();
    let info = session.info();
    assert_eq!(info.verification_code.len(), 6);
    assert_eq!(info.host_fingerprint, host_id.fingerprint());

    let Ev::Accepted(granted) = next(&ev_rx) else {
        panic!("acceptation attendue");
    };
    assert_eq!(granted, ["view_screen", "control"]);
    let consent = app.consent.lock().unwrap().clone().unwrap();
    assert_eq!(consent.viewer_name, "Pixel de test");
    assert_eq!(consent.device_id, viewer_id.device_id());
    assert_eq!(consent.verification_code, info.verification_code);
    match next(&status_rx) {
        HostStatus::SessionStarted {
            peer_id,
            verification_code,
            ..
        } => {
            assert_eq!(peer_id, viewer_id.device_id());
            assert_eq!(verification_code, info.verification_code);
        }
        other => panic!("début de session attendu : {other:?}"),
    }

    let Ev::Video(cfg) = next(&ev_rx) else {
        panic!("configuration vidéo attendue");
    };
    assert_eq!((cfg.width, cfg.height), (360, 640));
    assert_eq!(cfg.encoder, "MediaCodec simulé");
    assert_eq!(cfg.bitrate_bps, 1_500_000);

    // Images : la première est une image clé (demandée à l'ouverture).
    let mut frames = 0;
    while frames < 10 {
        match next(&ev_rx) {
            Ev::Frame(f) => {
                if frames == 0 {
                    assert!(f.keyframe);
                }
                assert_eq!(f.data.len(), 200);
                session.ack(f.frame_id);
                frames += 1;
            }
            Ev::Video(_) => {}
            _ => panic!("image attendue"),
        }
    }

    // Entrées : touche A (HID 0x04 → KEYCODE_A 29) et un toucher.
    session.key(0x04, true);
    session.pointer(0, 0.5, 0.25, 1, 0.0, 0.0);
    session.key(0x04, false);
    session.pointer(0, 0.5, 0.25, 0, 0.0, 0.0);
    let expected = [
        "key 0x4 Some(29) true",
        "pointer 0.5 0.25 1",
        "key 0x4 Some(29) false",
        "pointer 0.5 0.25 0",
    ];
    for _ in 0..200 {
        let log = app.log.lock().unwrap().clone();
        if log.len() >= expected.len() {
            assert_eq!(log[..expected.len()], expected);
            break;
        }
        // Le viewer continue d'acquitter pour garder le flux vivant.
        if let Ok(Ev::Frame(f)) = ev_rx.recv_timeout(Duration::from_millis(20)) {
            session.ack(f.frame_id);
        }
    }

    session.disconnect();
    loop {
        match next(&ev_rx) {
            Ev::Ended => break,
            Ev::Frame(_) | Ev::Video(_) | Ev::Accepted(_) => {}
        }
    }
    match next(&status_rx) {
        HostStatus::SessionEnded { peer_id, .. } => assert_eq!(peer_id, viewer_id.device_id()),
        other => panic!("fin de session attendue : {other:?}"),
    }
    assert!(app.log.lock().unwrap().contains(&"stop".to_string()));
    assert!(!*app.streaming.lock().unwrap());

    service.stop();
    assert!(matches!(next(&status_rx), HostStatus::Stopped));
    drop(server);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn bad_inputs_are_reported() {
    let dir = temp_dir("bad");
    let id = Identity::load_or_create(dir.join("v.identity").display().to_string()).unwrap();
    struct Silent;
    impl ViewerListener for Silent {
        fn on_accepted(&self, _: Vec<String>, _: Vec<Display>) {}
        fn on_video_config(&self, _: VideoConfig) {}
        fn on_displays(&self, _: Vec<Display>) {}
        fn on_frame(&self, _: VideoFrame) {}
        fn on_ended(&self, _: String, _: String) {}
    }
    let request = |target: &str, pin: &str| ConnectRequest {
        server: ServerConfig {
            address: "127.0.0.1:9".into(),
            pin: pin.into(),
        },
        target: target.into(),
        api_url: None,
        api_token: None,
        view_only: true,
        display_name: "x".into(),
    };
    let err = |r: Result<_, MobileError>| r.err().expect("erreur attendue");
    assert!(matches!(
        err(connect(
            id.clone(),
            request("12", "x"),
            Arc::new(Silent),
            None
        )),
        MobileError::Invalid { .. }
    ));
    assert!(matches!(
        err(connect(
            id,
            request("123456789", "pas une empreinte"),
            Arc::new(Silent),
            None
        )),
        MobileError::Invalid { .. }
    ));
    let _ = std::fs::remove_dir_all(dir);
}
