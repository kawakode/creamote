//! Session `org.freedesktop.portal.RemoteDesktop` (avec ScreenCast) par
//! D-Bus : une seule autorisation pour l'image et les entrées. Le jeton de
//! restauration est conservé pour que les sessions suivantes (accès sans
//! surveillance) ne redemandent pas l'autorisation tant qu'elle n'est pas
//! révoquée.

use std::collections::HashMap;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

use crate::{CaptureError, Result};

const DEST: &str = "org.freedesktop.portal.Desktop";
const PATH: &str = "/org/freedesktop/portal/desktop";
const REMOTE_DESKTOP: &str = "org.freedesktop.portal.RemoteDesktop";
const SCREEN_CAST: &str = "org.freedesktop.portal.ScreenCast";

/// Temps laissé à l'utilisateur pour répondre à la boîte du portail.
const DIALOG_TIMEOUT: Duration = Duration::from_secs(120);
/// Une session inutilisée est fermée après ce délai (l'indicateur de
/// partage d'écran disparaît).
const LINGER: Duration = Duration::from_secs(15);

pub const KEYBOARD: u32 = 1;
pub const POINTER: u32 = 2;

fn err(e: impl std::fmt::Display) -> CaptureError {
    CaptureError::Backend(format!("portail : {e}"))
}

/// Flux d'un écran partagé par le portail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stream {
    /// Nœud PipeWire.
    pub node_id: u32,
    pub x: i32,
    pub y: i32,
    /// Taille logique (celle des coordonnées du pointeur).
    pub width: u32,
    pub height: u32,
}

/// Session ouverte auprès du portail.
pub struct PortalSession {
    conn: Connection,
    handle: OwnedObjectPath,
    streams: Vec<Stream>,
    devices: u32,
    closed: AtomicBool,
    last_used: Mutex<Instant>,
}

impl std::fmt::Debug for PortalSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortalSession")
            .field("handle", &self.handle.as_str())
            .field("streams", &self.streams)
            .field("devices", &self.devices)
            .finish_non_exhaustive()
    }
}

static CURRENT: Mutex<Option<Arc<PortalSession>>> = Mutex::new(None);

/// Session courante, ouverte au besoin (boîte du portail sauf jeton de
/// restauration valide). Partagée par la capture et l'injection.
pub fn session() -> Result<Arc<PortalSession>> {
    let mut cur = CURRENT.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = cur.as_ref().filter(|s| !s.is_closed()) {
        *s.last_used.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
        return Ok(s.clone());
    }
    if let Some(old) = cur.take() {
        old.close();
    }
    let s = Arc::new(PortalSession::open()?);
    *cur = Some(s.clone());
    std::thread::Builder::new()
        .name("creamote-portal-reaper".into())
        .spawn(reaper)
        .map_err(err)?;
    Ok(s)
}

/// Ferme la session quand plus personne ne l'utilise depuis [`LINGER`].
fn reaper() {
    loop {
        std::thread::sleep(Duration::from_secs(2));
        let mut cur = CURRENT.lock().unwrap_or_else(|e| e.into_inner());
        let Some(s) = cur.as_ref() else { return };
        let idle = s
            .last_used
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .elapsed();
        if s.is_closed() || (Arc::strong_count(s) == 1 && idle > LINGER) {
            if let Some(s) = cur.take() {
                s.close();
            }
            return;
        }
    }
}

impl PortalSession {
    fn open() -> Result<Self> {
        let conn = Connection::session()
            .map_err(|e| CaptureError::Unsupported(format!("bus D-Bus de session : {e}")))?;
        let desktop = |iface| Proxy::new(&conn, DEST, PATH, iface).map_err(err);
        let rd = desktop(REMOTE_DESKTOP)?;
        let sc = desktop(SCREEN_CAST)?;
        let rd_version: u32 = rd.get_property("version").map_err(|e| {
            CaptureError::Unsupported(format!(
                "portail RemoteDesktop absent (xdg-desktop-portal et son backend) : {e}"
            ))
        })?;
        let available_devices: u32 = rd.get_property("AvailableDeviceTypes").unwrap_or(3);
        let cursor_modes: u32 = sc.get_property("AvailableCursorModes").unwrap_or(1);

        let r = request(&conn, |token| {
            let mut o = options(token);
            o.insert("session_handle_token", Value::from(token));
            rd.call("CreateSession", &(o,))
        })?;
        let handle: String = take(&r, "session_handle")?;
        let handle = OwnedObjectPath::try_from(handle).map_err(err)?;
        let mut session = Self {
            conn: conn.clone(),
            handle: handle.clone(),
            streams: Vec::new(),
            devices: 0,
            closed: AtomicBool::new(false),
            last_used: Mutex::new(Instant::now()),
        };
        let path = &handle;

        let token = restore_token();
        request(&conn, |t| {
            let mut o = options(t);
            o.insert(
                "types",
                Value::from(available_devices & (KEYBOARD | POINTER)),
            );
            if rd_version >= 2 {
                // Conservée jusqu'à révocation par l'utilisateur.
                o.insert("persist_mode", Value::from(2u32));
                if let Some(token) = token.as_deref() {
                    o.insert("restore_token", Value::from(token));
                }
            }
            rd.call("SelectDevices", &(path, o))
        })?;
        request(&conn, |t| {
            let mut o = options(t);
            o.insert("types", Value::from(1u32)); // écrans
            o.insert("multiple", Value::from(true));
            // Curseur incrusté dans l'image si possible.
            let mode = if cursor_modes & 2 != 0 { 2u32 } else { 1 };
            o.insert("cursor_mode", Value::from(mode));
            sc.call("SelectSources", &(path, o))
        })?;
        let r = request(&conn, |t| rd.call("Start", &(path, "", options(t))))?;

        let devices: u32 = take(&r, "devices").unwrap_or(0);
        if let Ok(token) = take::<String>(&r, "restore_token") {
            save_restore_token(&token);
        }
        let streams: Vec<(u32, HashMap<String, OwnedValue>)> = take(&r, "streams")?;
        let streams = streams
            .into_iter()
            .map(|(node_id, props)| {
                let (x, y) = take::<(i32, i32)>(&props, "position").unwrap_or((0, 0));
                let (w, h) = take::<(i32, i32)>(&props, "size").unwrap_or((0, 0));
                Stream {
                    node_id,
                    x,
                    y,
                    width: w.max(0) as u32,
                    height: h.max(0) as u32,
                }
            })
            .collect::<Vec<_>>();
        if streams.is_empty() {
            return Err(CaptureError::PermissionDenied(" : aucun écran partagé"));
        }
        tracing::info!(
            "session du portail ouverte : {} écran(s), périphériques {devices:#x}",
            streams.len()
        );
        session.streams = streams;
        session.devices = devices;
        Ok(session)
    }

    pub fn streams(&self) -> &[Stream] {
        &self.streams
    }

    /// Périphériques accordés ([`KEYBOARD`], [`POINTER`]).
    pub fn devices(&self) -> u32 {
        self.devices
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    /// Marque la session comme perdue (révoquée, portail redémarré) : la
    /// prochaine demande en ouvrira une autre.
    pub fn mark_closed(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }

    /// Connexion PipeWire donnant accès aux flux de la session.
    pub fn pipewire_fd(&self) -> Result<OwnedFd> {
        let sc = Proxy::new(&self.conn, DEST, PATH, SCREEN_CAST).map_err(err)?;
        let fd: zbus::zvariant::OwnedFd = sc
            .call(
                "OpenPipeWireRemote",
                &(&self.handle, HashMap::<&str, Value>::new()),
            )
            .map_err(err)?;
        Ok(fd.into())
    }

    fn notify<B>(&self, method: &str, body: B) -> Result<()>
    where
        B: zbus::export::serde::Serialize + zbus::zvariant::DynamicType,
    {
        if self.is_closed() {
            return Err(err("session fermée"));
        }
        self.conn
            .call_method(Some(DEST), PATH, Some(REMOTE_DESKTOP), method, &body)
            .map(drop)
            .map_err(err)
    }

    fn empty() -> HashMap<&'static str, Value<'static>> {
        HashMap::new()
    }

    /// Touche par code evdev.
    pub fn key(&self, evdev: u16, pressed: bool) -> Result<()> {
        self.notify(
            "NotifyKeyboardKeycode",
            (
                &self.handle,
                Self::empty(),
                i32::from(evdev),
                u32::from(pressed),
            ),
        )
    }

    /// Position absolue en coordonnées logiques du flux `node_id`.
    pub fn motion(&self, node_id: u32, x: f64, y: f64) -> Result<()> {
        self.notify(
            "NotifyPointerMotionAbsolute",
            (&self.handle, Self::empty(), node_id, x, y),
        )
    }

    /// Bouton par code evdev (`BTN_LEFT` = 0x110…).
    pub fn button(&self, code: i32, pressed: bool) -> Result<()> {
        self.notify(
            "NotifyPointerButton",
            (&self.handle, Self::empty(), code, u32::from(pressed)),
        )
    }

    /// Crans de molette ; `horizontal` : axe 1, sinon axe 0 (positif vers
    /// le bas / la droite).
    pub fn scroll(&self, horizontal: bool, steps: i32) -> Result<()> {
        self.notify(
            "NotifyPointerAxisDiscrete",
            (&self.handle, Self::empty(), u32::from(horizontal), steps),
        )
    }

    fn close(&self) {
        self.mark_closed();
        let _ = self.conn.call_method(
            Some(DEST),
            &self.handle,
            Some("org.freedesktop.portal.Session"),
            "Close",
            &(),
        );
        tracing::info!("session du portail fermée");
    }
}

impl Drop for PortalSession {
    fn drop(&mut self) {
        if !self.is_closed() {
            self.close();
        }
    }
}

fn options(token: &str) -> HashMap<&'static str, Value<'_>> {
    HashMap::from([("handle_token", Value::from(token))])
}

fn take<T>(map: &HashMap<String, OwnedValue>, key: &str) -> Result<T>
where
    T: TryFrom<OwnedValue>,
    T::Error: std::fmt::Display,
{
    let v = map
        .get(key)
        .ok_or_else(|| err(format!("réponse sans « {key} »")))?;
    T::try_from(v.try_clone().map_err(err)?).map_err(err)
}

/// Appel suivant le schéma `Request` du portail : la réponse arrive par le
/// signal `Response` de l'objet `request/<émetteur>/<jeton>`, auquel on
/// s'abonne avant l'appel.
fn request<F>(conn: &Connection, call: F) -> Result<HashMap<String, OwnedValue>>
where
    F: FnOnce(&str) -> zbus::Result<OwnedObjectPath>,
{
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let token = format!(
        "creamote{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let sender = conn
        .unique_name()
        .ok_or_else(|| err("connexion D-Bus sans nom"))?
        .trim_start_matches(':')
        .replace('.', "_");
    let path = format!("{PATH}/request/{sender}/{token}");
    let req = Proxy::new(conn, DEST, path, "org.freedesktop.portal.Request").map_err(err)?;
    let mut responses = req.receive_signal("Response").map_err(err)?;
    let (tx, rx) = mpsc::channel();
    // L'itérateur bloque : attente dans un fil pour pouvoir abandonner.
    let waiter = std::thread::Builder::new()
        .name("creamote-portal-request".into())
        .spawn(move || {
            let r = responses.next().map(|m| {
                m.body()
                    .deserialize::<(u32, HashMap<String, OwnedValue>)>()
                    .map_err(err)
            });
            let _ = tx.send(r);
        })
        .map_err(err)?;
    let actual = call(&token).map_err(err)?;
    if actual.as_str() != req.path().as_str() {
        // Ancien portail (< 0.9) qui n'honore pas le jeton.
        return Err(CaptureError::Unsupported(
            "xdg-desktop-portal trop ancien".into(),
        ));
    }
    let r = match rx.recv_timeout(DIALOG_TIMEOUT) {
        Ok(Some(r)) => r?,
        Ok(None) => return Err(err("portail déconnecté")),
        Err(_) => {
            let _ = req.call_method("Close", &());
            drop(waiter);
            return Err(CaptureError::PermissionDenied(
                " : pas de réponse à la demande de partage d'écran",
            ));
        }
    };
    match r {
        (0, results) => Ok(results),
        (1, _) => Err(CaptureError::PermissionDenied(
            " : partage d'écran refusé dans la boîte du portail",
        )),
        (code, _) => Err(err(format!("demande interrompue ({code})"))),
    }
}

fn token_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_STATE_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))?;
    Some(base.join("creamote").join("portal-restore-token"))
}

fn restore_token() -> Option<String> {
    let t = std::fs::read_to_string(token_path()?).ok()?;
    let t = t.trim();
    (!t.is_empty()).then(|| t.to_owned())
}

fn save_restore_token(token: &str) {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let Some(path) = token_path() else { return };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let r = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .and_then(|mut f| f.write_all(token.as_bytes()));
    if let Err(e) = r {
        tracing::warn!("jeton du portail non enregistré ({}) : {e}", path.display());
    }
}
