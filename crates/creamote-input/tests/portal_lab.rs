//! Capture et injection Wayland face à un faux xdg-desktop-portal et un
//! vrai démon PipeWire (`tools/wayland-lab.sh`) : vérifie le dialogue D-Bus
//! (jetons de requête, session, jeton de restauration), la réception du
//! flux PipeWire et les appels `Notify*` produits par l'injecteur.
#![cfg(all(target_os = "linux", feature = "wayland"))]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use creamote_input::{Injector, Pointer};
use zbus::object_server::SignalEmitter;
use zbus::zvariant::{ObjectPath, OwnedFd, OwnedValue, Value};

type Calls = Arc<Mutex<Vec<String>>>;

struct Portal {
    calls: Calls,
    node: u32,
}

async fn respond(
    conn: &zbus::Connection,
    hdr: &zbus::message::Header<'_>,
    options: &HashMap<String, OwnedValue>,
    results: HashMap<&str, Value<'_>>,
) -> zbus::fdo::Result<ObjectPath<'static>> {
    let token: String = options
        .get("handle_token")
        .and_then(|v| String::try_from(v.try_clone().ok()?).ok())
        .ok_or_else(|| zbus::fdo::Error::InvalidArgs("handle_token".into()))?;
    let sender = hdr
        .sender()
        .unwrap()
        .trim_start_matches(':')
        .replace('.', "_");
    let path = ObjectPath::try_from(format!(
        "/org/freedesktop/portal/desktop/request/{sender}/{token}"
    ))
    .unwrap()
    .into_owned();
    let emitter = SignalEmitter::new(conn, path.clone())?;
    emitter
        .emit(
            "org.freedesktop.portal.Request",
            "Response",
            &(0u32, results),
        )
        .await?;
    Ok(path)
}

#[zbus::interface(name = "org.freedesktop.portal.RemoteDesktop")]
impl Portal {
    #[zbus(property, name = "version")]
    fn version(&self) -> u32 {
        2
    }

    #[zbus(property)]
    fn available_device_types(&self) -> u32 {
        3
    }

    async fn create_session(
        &self,
        options: HashMap<String, OwnedValue>,
        #[zbus(connection)] conn: &zbus::Connection,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
    ) -> zbus::fdo::Result<ObjectPath<'static>> {
        self.calls.lock().unwrap().push("CreateSession".into());
        let handle = "/org/freedesktop/portal/desktop/session/lab/s1";
        respond(
            conn,
            &hdr,
            &options,
            HashMap::from([("session_handle", Value::from(handle))]),
        )
        .await
    }

    async fn select_devices(
        &self,
        _session: ObjectPath<'_>,
        options: HashMap<String, OwnedValue>,
        #[zbus(connection)] conn: &zbus::Connection,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
    ) -> zbus::fdo::Result<ObjectPath<'static>> {
        let restore = options
            .get("restore_token")
            .and_then(|v| String::try_from(v.try_clone().ok()?).ok())
            .unwrap_or_default();
        let types = options
            .get("types")
            .and_then(|v| u32::try_from(v.try_clone().ok()?).ok())
            .unwrap_or(0);
        self.calls
            .lock()
            .unwrap()
            .push(format!("SelectDevices types={types} restore={restore}"));
        respond(conn, &hdr, &options, HashMap::new()).await
    }

    async fn start(
        &self,
        _session: ObjectPath<'_>,
        _parent: String,
        options: HashMap<String, OwnedValue>,
        #[zbus(connection)] conn: &zbus::Connection,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
    ) -> zbus::fdo::Result<ObjectPath<'static>> {
        self.calls.lock().unwrap().push("Start".into());
        let props = HashMap::from([
            ("position", Value::from((1920i32, 0i32))),
            ("size", Value::from((640i32, 360i32))),
        ]);
        let streams = vec![(self.node, props)];
        respond(
            conn,
            &hdr,
            &options,
            HashMap::from([
                ("devices", Value::from(3u32)),
                ("streams", Value::from(streams)),
                ("restore_token", Value::from("jeton-lab")),
            ]),
        )
        .await
    }

    fn notify_keyboard_keycode(
        &self,
        _s: ObjectPath<'_>,
        _o: HashMap<String, OwnedValue>,
        keycode: i32,
        state: u32,
    ) {
        self.calls
            .lock()
            .unwrap()
            .push(format!("key {keycode} {state}"));
    }

    fn notify_pointer_motion_absolute(
        &self,
        _s: ObjectPath<'_>,
        _o: HashMap<String, OwnedValue>,
        stream: u32,
        x: f64,
        y: f64,
    ) {
        self.calls
            .lock()
            .unwrap()
            .push(format!("motion {stream} {x:.0} {y:.0}"));
    }

    fn notify_pointer_button(
        &self,
        _s: ObjectPath<'_>,
        _o: HashMap<String, OwnedValue>,
        button: i32,
        state: u32,
    ) {
        self.calls
            .lock()
            .unwrap()
            .push(format!("button {button:#x} {state}"));
    }

    fn notify_pointer_axis_discrete(
        &self,
        _s: ObjectPath<'_>,
        _o: HashMap<String, OwnedValue>,
        axis: u32,
        steps: i32,
    ) {
        self.calls
            .lock()
            .unwrap()
            .push(format!("axis {axis} {steps}"));
    }
}

struct ScreenCast {
    calls: Calls,
}

#[zbus::interface(name = "org.freedesktop.portal.ScreenCast")]
impl ScreenCast {
    #[zbus(property)]
    fn available_cursor_modes(&self) -> u32 {
        3
    }

    async fn select_sources(
        &self,
        _session: ObjectPath<'_>,
        options: HashMap<String, OwnedValue>,
        #[zbus(connection)] conn: &zbus::Connection,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
    ) -> zbus::fdo::Result<ObjectPath<'static>> {
        let cursor = options
            .get("cursor_mode")
            .and_then(|v| u32::try_from(v.try_clone().ok()?).ok())
            .unwrap_or(0);
        self.calls
            .lock()
            .unwrap()
            .push(format!("SelectSources cursor={cursor}"));
        respond(conn, &hdr, &options, HashMap::new()).await
    }

    fn open_pipe_wire_remote(
        &self,
        _session: ObjectPath<'_>,
        _o: HashMap<String, OwnedValue>,
    ) -> zbus::fdo::Result<OwnedFd> {
        self.calls.lock().unwrap().push("OpenPipeWireRemote".into());
        let dir = std::env::var("XDG_RUNTIME_DIR").unwrap();
        let s = std::os::unix::net::UnixStream::connect(format!("{dir}/pipewire-0"))
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        Ok(std::os::fd::OwnedFd::from(s).into())
    }
}

struct Session {
    calls: Calls,
}

#[zbus::interface(name = "org.freedesktop.portal.Session")]
impl Session {
    fn close(&self) {
        self.calls.lock().unwrap().push("Close".into());
    }
}

#[test]
#[ignore = "nécessite tools/wayland-lab.sh (bus D-Bus et PipeWire de test)"]
fn capture_and_input_through_the_portal() {
    let node: u32 = std::env::var("CREAMOTE_LAB_NODE")
        .expect("CREAMOTE_LAB_NODE")
        .parse()
        .unwrap();
    // Exportées par le script (set_var demanderait du code unsafe).
    assert_eq!(
        std::env::var("CREAMOTE_LINUX_BACKEND").as_deref(),
        Ok("portal")
    );
    let state = std::env::var("XDG_STATE_HOME").expect("XDG_STATE_HOME");

    let calls: Calls = Arc::default();
    let _server = zbus::blocking::connection::Builder::session()
        .unwrap()
        .name("org.freedesktop.portal.Desktop")
        .unwrap()
        .serve_at(
            "/org/freedesktop/portal/desktop",
            Portal {
                calls: calls.clone(),
                node,
            },
        )
        .unwrap()
        .serve_at(
            "/org/freedesktop/portal/desktop",
            ScreenCast {
                calls: calls.clone(),
            },
        )
        .unwrap()
        .serve_at(
            "/org/freedesktop/portal/desktop/session/lab/s1",
            Session {
                calls: calls.clone(),
            },
        )
        .unwrap()
        .build()
        .unwrap();

    // Écrans annoncés par le portail.
    let displays = creamote_capture::displays().unwrap();
    assert_eq!(displays.len(), 1);
    let d = displays[0].clone();
    assert_eq!((d.id, d.x, d.width, d.height), (node, 1920, 640, 360));

    // Image du flux PipeWire (couleur unie BGRx du labo).
    let mut cap = creamote_capture::open(Some(node)).unwrap();
    let start = Instant::now();
    let frame = loop {
        assert!(start.elapsed() < Duration::from_secs(10), "aucune image");
        if let Some(f) = cap.next_frame(Duration::from_millis(500)).unwrap() {
            break f;
        }
    };
    assert_eq!((frame.width, frame.height), (640, 360));
    let px = &frame.row(180)[320 * 4..320 * 4 + 3];
    assert_eq!(px, [0xe0, 0x50, 0x20], "BGR attendu");

    // Entrées : même session (pas de seconde boîte), coordonnées du flux.
    let mut inj = Injector::open(d).unwrap();
    inj.key(0x04, true).unwrap(); // A → evdev 30
    inj.key(0x04, false).unwrap();
    inj.pointer(&Pointer {
        x: 0.5,
        y: 0.25,
        buttons: 1,
        ..Default::default()
    })
    .unwrap();
    inj.pointer(&Pointer {
        x: 0.5,
        y: 0.25,
        wheel_dy: 2.0,
        ..Default::default()
    })
    .unwrap();
    drop(inj);
    drop(cap);

    let log = calls.lock().unwrap().clone();
    let expected = [
        "CreateSession",
        "SelectDevices types=3 restore=",
        "SelectSources cursor=2",
        "Start",
        "OpenPipeWireRemote",
        "key 30 1",
        "key 30 0",
        &format!("motion {node} 320 90"),
        "button 0x110 1",
        "button 0x110 0",
        "axis 0 2",
    ];
    assert_eq!(log, expected, "appels au portail");
    let token = std::fs::read_to_string(format!("{state}/creamote/portal-restore-token")).unwrap();
    assert_eq!(token, "jeton-lab");

    // Session inutilisée : fermée par le portail après le délai.
    let start = Instant::now();
    while !calls.lock().unwrap().iter().any(|c| c == "Close") {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "session non fermée"
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    // Nouvelle session : le jeton de restauration est présenté.
    creamote_capture::displays().unwrap();
    assert!(
        calls
            .lock()
            .unwrap()
            .iter()
            .any(|c| c == "SelectDevices types=3 restore=jeton-lab")
    );
}
