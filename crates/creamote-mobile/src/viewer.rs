//! Session viewer : l'app affiche et pilote un autre appareil.

use std::sync::{Arc, Mutex};

use creamote_crypto::{DeviceId, DeviceIdentity};
use creamote_net::rendezvous::RendezvousClient;
use creamote_net::secure::SecureChannel;
use creamote_net::stream::PeerPath;
use creamote_proto::permissions::Permissions;
use creamote_proto::session::v1::PointerEvent;
use creamote_session::viewer::{self, Event, Handle};
use creamote_session::{DEFAULT_FPS, Sharing};

use crate::clipboard::{AppClipboard, ClipboardProvider};
use crate::{Display, Identity, MobileError, RUNTIME, ServerConfig};

#[derive(Debug, Clone, uniffi::Record)]
pub struct ConnectRequest {
    pub server: ServerConfig,
    /// ID à 9 chiffres de l'appareil à joindre.
    pub target: String,
    /// API de gestion du serveur auto-hébergé et jeton de l'utilisateur :
    /// ticket de session pour un host enrôlé.
    pub api_url: Option<String>,
    pub api_token: Option<String>,
    pub view_only: bool,
    /// Nom présenté à l'utilisateur du host.
    pub display_name: String,
}

/// Canal établi, avant l'acceptation par le host.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ConnectedInfo {
    /// Code à 6 chiffres à comparer avec celui affiché par le host.
    pub verification_code: String,
    pub host_fingerprint: String,
    /// Connexion directe (sinon par le relay).
    pub direct: bool,
    /// Durée maximale imposée par le serveur public (relay seulement) ;
    /// 0 : illimitée.
    pub max_session_seconds: u32,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct VideoConfig {
    pub display_id: u32,
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub bitrate_bps: u32,
    pub encoder: String,
}

/// Image H.264 Annex B complète ; à acquitter une fois décodée.
#[derive(Debug, Clone, uniffi::Record)]
pub struct VideoFrame {
    pub display_id: u32,
    pub frame_id: u64,
    pub keyframe: bool,
    pub timestamp_us: u64,
    pub data: Vec<u8>,
}

/// Événements de la session, appelés depuis un thread dédié, dans l'ordre.
#[uniffi::export(with_foreign)]
pub trait ViewerListener: Send + Sync {
    /// Le host a accepté ; `granted` : noms des permissions accordées.
    fn on_accepted(&self, granted: Vec<String>, displays: Vec<Display>);
    /// Nouveau flux (début, changement d'écran, de taille ou de débit).
    fn on_video_config(&self, config: VideoConfig);
    fn on_displays(&self, displays: Vec<Display>);
    fn on_frame(&self, frame: VideoFrame);
    /// Fin de session ; plus aucun appel ensuite.
    fn on_ended(&self, reason: String, message: String);
}

/// Session en cours. Les commandes sont ordonnées et ne bloquent pas.
#[derive(uniffi::Object)]
pub struct ViewerSession {
    handle: Handle,
    info: ConnectedInfo,
    /// Le client de rendezvous reste ouvert pendant la session.
    rendezvous: Mutex<Option<RendezvousClient>>,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.is_ascii() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Ticket de session auprès de l'API de gestion (host enrôlé).
async fn fetch_ticket(
    api_url: &str,
    token: &str,
    target: DeviceId,
    identity: &DeviceIdentity,
) -> Result<Vec<u8>, MobileError> {
    let url = format!("{}/api/v1/tickets", api_url.trim_end_matches('/'));
    let resp = reqwest::Client::new()
        .post(&url)
        .bearer_auth(token)
        .json(&serde_json::json!({
            "device_id": target.to_string(),
            "viewer_key": hex(identity.public().signing_key()),
        }))
        .send()
        .await
        .map_err(|e| MobileError::network(format!("requête {url} : {e}")))?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or_default();
    if !status.is_success() {
        return Err(MobileError::refused(format!(
            "ticket refusé : {status} {}",
            body["message"].as_str().unwrap_or_default()
        )));
    }
    body["ticket"]
        .as_str()
        .and_then(unhex)
        .ok_or_else(|| MobileError::network("réponse sans ticket"))
}

/// Ouvre une session vers `request.target` (bloquant : à appeler hors du
/// thread principal). `clipboard` : partage du presse-papier (texte).
#[uniffi::export]
pub fn connect(
    identity: Arc<Identity>,
    request: ConnectRequest,
    listener: Arc<dyn ViewerListener>,
    clipboard: Option<Arc<dyn ClipboardProvider>>,
) -> Result<Arc<ViewerSession>, MobileError> {
    RUNTIME.block_on(open(identity, request, listener, clipboard))
}

async fn open(
    identity: Arc<Identity>,
    request: ConnectRequest,
    listener: Arc<dyn ViewerListener>,
    clipboard: Option<Arc<dyn ClipboardProvider>>,
) -> Result<Arc<ViewerSession>, MobileError> {
    let identity = &identity.inner;
    let target = DeviceId::parse(request.target.trim())
        .ok_or_else(|| MobileError::invalid("ID invalide (9 chiffres attendus)"))?;
    let pin = request.server.pin()?;
    let addr = request.server.resolve().await?;
    let ticket = match (&request.api_url, &request.api_token) {
        (Some(url), Some(token)) if !url.is_empty() && !token.is_empty() => {
            fetch_ticket(url, token, target, identity).await?
        }
        _ => Vec::new(),
    };

    let mut rv = RendezvousClient::register(addr, pin, identity)
        .await
        .map_err(|e| MobileError::network(format!("connexion au serveur : {e}")))?;
    let grant = rv
        .request_session_with_ticket(target, ticket)
        .await
        .map_err(MobileError::refused)?;
    let stream = rv
        .connector()
        .viewer(&grant)
        .await
        .map_err(MobileError::network)?;
    let direct = stream.path() == PeerPath::Direct;
    let chan = SecureChannel::initiate(stream, identity)
        .await
        .map_err(MobileError::network)?;
    if chan.remote().device_id() != target {
        return Err(MobileError::refused(format!(
            "le pair authentifié n'est pas {target}"
        )));
    }
    let info = ConnectedInfo {
        verification_code: chan.verification_code().to_string(),
        host_fingerprint: chan.remote().fingerprint(),
        direct,
        // La limite du serveur public ne s'applique qu'au relay.
        max_session_seconds: if direct { 0 } else { grant.max_session_seconds },
    };

    let requested = if request.view_only {
        Permissions::VIEW
    } else {
        Permissions::VIEW | Permissions::CONTROL
    };
    let sharing = Sharing {
        clipboard: clipboard.map(|c| Box::new(AppClipboard(c)) as _),
        files: None,
    };
    let (tx, rx) = chan.split();
    let (handle, mut events) = viewer::start_with(
        tx,
        rx,
        viewer::Options {
            display_name: request.display_name.chars().take(64).collect(),
            requested,
            ..Default::default()
        },
        sharing,
    );

    // Les rappels Kotlin peuvent bloquer : thread dédié, hors du runtime.
    std::thread::Builder::new()
        .name("creamote-viewer-events".into())
        .spawn(move || {
            while let Some(ev) = RUNTIME.block_on(events.recv()) {
                match ev {
                    Event::Accepted { granted, displays } => listener.on_accepted(
                        granted.names().into_iter().map(String::from).collect(),
                        displays.iter().map(Display::from).collect(),
                    ),
                    Event::Video(c) => listener.on_video_config(VideoConfig {
                        display_id: c.display_id,
                        width: c.width,
                        height: c.height,
                        fps: c.max_fps,
                        bitrate_bps: c.target_bitrate_bps,
                        encoder: c.encoder,
                    }),
                    Event::Displays(d) => {
                        listener.on_displays(d.iter().map(Display::from).collect())
                    }
                    Event::Frame(f) => listener.on_frame(VideoFrame {
                        display_id: f.display_id,
                        frame_id: f.frame_id,
                        keyframe: f.keyframe,
                        timestamp_us: f.timestamp_us,
                        data: f.data,
                    }),
                    // Fichiers : pas encore proposés par l'app.
                    Event::Files(_) => {}
                    Event::Ended { reason, message } => {
                        listener.on_ended(format!("{reason:?}"), message);
                        return;
                    }
                }
            }
            listener.on_ended("Closed".into(), String::new());
        })
        .map_err(|e| MobileError::App {
            detail: e.to_string(),
        })?;

    Ok(Arc::new(ViewerSession {
        handle,
        info,
        rendezvous: Mutex::new(Some(rv)),
    }))
}

#[uniffi::export]
impl ViewerSession {
    pub fn info(&self) -> ConnectedInfo {
        self.info.clone()
    }

    /// Touche physique (usage HID, voir `hidFromAndroidKeycode`).
    pub fn key(&self, hid: u32, pressed: bool) {
        let _ = RUNTIME.block_on(self.handle.key(hid, pressed));
    }

    /// Pointeur en coordonnées normalisées [0, 1] sur l'écran diffusé.
    /// `buttons` : bit 0 gauche, 1 droit, 2 milieu.
    pub fn pointer(
        &self,
        display_id: u32,
        x: f32,
        y: f32,
        buttons: u32,
        wheel_dx: f32,
        wheel_dy: f32,
    ) {
        let p = PointerEvent {
            display_id,
            x,
            y,
            buttons,
            wheel_dx,
            wheel_dy,
        };
        let _ = RUNTIME.block_on(self.handle.pointer(p));
    }

    /// Image décodée : le host n'en garde que quelques-unes en vol.
    pub fn ack(&self, frame_id: u64) {
        let _ = RUNTIME.block_on(self.handle.ack(frame_id));
    }

    /// À appeler si le décodeur a perdu le fil (erreur, surface recréée).
    pub fn request_keyframe(&self) {
        let _ = RUNTIME.block_on(self.handle.request_keyframe());
    }

    pub fn select_display(&self, display_id: u32) {
        let _ = RUNTIME.block_on(self.handle.select_display(display_id, DEFAULT_FPS, 0));
    }

    /// Termine la session (`close` est réservé par `AutoCloseable`).
    pub fn disconnect(&self) {
        RUNTIME.block_on(self.handle.close());
        if let Some(rv) = self.rendezvous.lock().expect("verrou sain").take() {
            let _rt = RUNTIME.enter();
            rv.close();
        }
    }
}
