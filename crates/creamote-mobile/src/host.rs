//! Host : l'app partage l'écran de l'appareil Android.
//!
//! L'app capture et encode elle-même (MediaProjection rend dans la surface
//! d'entrée d'un encodeur MediaCodec) et pousse les images encodées par
//! [`HostService::push_frame`]. Le cœur garde le protocole : consentement,
//! tickets, contrôle de flux, débit adaptatif, chiffrement.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use creamote_capture::DisplayInfo;
use creamote_codec::EncodedFrame;
use creamote_crypto::{DeviceIdentity, PublicIdentity};
use creamote_input::{Button, Pointer};
use creamote_net::ident;
use creamote_net::rendezvous::{Event, RegisterOptions, RelayGrant, RendezvousClient};
use creamote_net::secure::SecureChannel;
use creamote_net::stream::PeerPath;
use creamote_net::ticket::{self, Decision, Enrollment};
use creamote_net::tls::ServerPin;
use creamote_proto::permissions::Permissions;
use creamote_session::creamote_transfer::files::AcceptPolicy;
use creamote_session::host::{
    self, Consent, ConsentPrompt, EncodedSource, InputSink, Media, Policy, SourceRequest,
};
use creamote_session::{FilesConfig, Sharing};
use tokio::sync::watch;

use crate::clipboard::{AppClipboard, ClipboardProvider};
use crate::keys::android_keycode;
use crate::{Display, Identity, MobileError, RUNTIME, ServerConfig};

#[derive(Debug, Clone, uniffi::Record)]
pub struct HostConfig {
    /// Serveur ; ignoré si l'appareil est déjà enrôlé (serveur d'enrôlement).
    pub server: Option<ServerConfig>,
    /// Fichier d'enrôlement (créé par `enroll_token`).
    pub enrollment_path: String,
    /// Jeton d'enrôlement créé par un administrateur dans la console.
    pub enroll_token: Option<String>,
    /// Nom de l'appareil à l'enrôlement, ex. « Galaxy Tab de l'accueil ».
    pub name: String,
    /// Toutes les sessions passent par le relay (adresse jamais communiquée).
    pub relay_only: bool,
    /// Dossier des fichiers reçus ; `None` : transfert refusé.
    pub files_dir: Option<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct EnrollmentInfo {
    pub server: String,
    pub entity_name: String,
    pub fleet_name: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ConsentRequest {
    /// Nom annoncé par le viewer (non vérifié).
    pub viewer_name: String,
    /// ID et empreinte prouvés par le handshake.
    pub device_id: String,
    pub fingerprint: String,
    /// Compte garanti par le ticket du serveur.
    pub user_email: Option<String>,
    /// À comparer de vive voix avec celui du viewer.
    pub verification_code: String,
    /// Permissions demandées (`view_screen`, `control`, `clipboard`…).
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ConsentAnswer {
    Deny,
    ViewOnly,
    Control,
}

#[derive(Debug, Clone, uniffi::Enum)]
pub enum HostStatus {
    /// Enregistré auprès du serveur, en attente de connexions.
    Online {
        address: String,
    },
    /// Serveur injoignable ; nouvelle tentative dans `retry_seconds`.
    Offline {
        message: String,
        retry_seconds: u32,
    },
    SessionStarted {
        peer_id: String,
        user_email: Option<String>,
        direct: bool,
        verification_code: String,
    },
    SessionEnded {
        peer_id: String,
        message: String,
    },
    /// Arrêté par [`HostService::stop`].
    Stopped,
}

/// Paramètres du flux demandé par le viewer.
#[derive(Debug, Clone, Copy, uniffi::Record)]
pub struct StreamRequest {
    pub fps: u32,
    /// 0 : au choix de l'app selon la résolution.
    pub bitrate_bps: u32,
}

/// Flux démarré par l'app.
#[derive(Debug, Clone, uniffi::Record)]
pub struct StreamInfo {
    /// Ex. « MediaCodec c2.exynos.h264.encoder ».
    pub encoder: String,
    pub bitrate_bps: u32,
}

/// Ce que l'app fait pour le host. Les appels viennent de threads du cœur
/// et peuvent bloquer (consentement : 30 s au plus).
#[uniffi::export(with_foreign)]
pub trait HostDelegate: Send + Sync {
    /// Écran courant (dimensions de la capture, qui suivent la rotation).
    fn screen(&self) -> Display;
    /// Demande à l'utilisateur présent ; appelé avant toute capture.
    fn consent(&self, request: ConsentRequest) -> ConsentAnswer;
    /// Démarre la capture et l'encodeur H.264 (sans images B), puis pousse
    /// les images par `HostService.pushFrame`.
    fn start_stream(&self, request: StreamRequest) -> Result<StreamInfo, MobileError>;
    fn stop_stream(&self);
    fn request_keyframe(&self);
    fn set_bitrate(&self, bps: u32);
    /// Touche physique : usage HID et code Android équivalent s'il existe.
    fn key(&self, hid: u32, android_keycode: Option<i32>, pressed: bool);
    /// Pointeur en coordonnées normalisées [0, 1] ; `buttons` : bit 0
    /// gauche (toucher), 1 droit (retour), 2 milieu (accueil).
    fn pointer(&self, x: f32, y: f32, buttons: u32, wheel_dx: f32, wheel_dy: f32);
    /// Fin de session : relâcher tout geste ou touche en cours.
    fn release_all(&self);
    fn on_status(&self, status: HostStatus);
}

/// Host en service.
#[derive(uniffi::Object)]
pub struct HostService {
    device_id: String,
    enrollment: Option<EnrollmentInfo>,
    frames: Arc<FrameQueue>,
    stop: watch::Sender<bool>,
}

/// Démarre le host : enregistrement (et enrôlement si `enroll_token`), puis
/// service des connexions en arrière-plan, avec reconnexion automatique.
/// Bloquant ; une erreur ici (empreinte, jeton) n'est pas réessayée.
#[uniffi::export]
pub fn start_host(
    identity: Arc<Identity>,
    config: HostConfig,
    delegate: Arc<dyn HostDelegate>,
    clipboard: Option<Arc<dyn ClipboardProvider>>,
) -> Result<Arc<HostService>, MobileError> {
    RUNTIME.block_on(start(identity.inner.clone(), config, delegate, clipboard))
}

#[uniffi::export]
impl HostService {
    pub fn device_id(&self) -> String {
        self.device_id.clone()
    }

    pub fn enrollment(&self) -> Option<EnrollmentInfo> {
        self.enrollment.clone()
    }

    /// Image H.264 Annex B produite par l'encodeur de l'app (`width` ×
    /// `height` : taille encodée). Ignorée hors d'un flux démarré.
    pub fn push_frame(&self, data: Vec<u8>, keyframe: bool, width: u32, height: u32) {
        self.frames.push(Pushed {
            frame: EncodedFrame {
                data,
                keyframe,
                captured_at: Instant::now(),
            },
            width,
            height,
        });
    }

    /// Se déconnecte du serveur et termine la session en cours.
    pub fn stop(&self) {
        let _ = self.stop.send(true);
        self.frames.close();
    }
}

struct Ctx {
    identity: Arc<DeviceIdentity>,
    enrollment: Option<Enrollment>,
    delegate: Arc<dyn HostDelegate>,
    clipboard: Option<Arc<dyn ClipboardProvider>>,
    files_dir: Option<PathBuf>,
    frames: Arc<FrameQueue>,
    /// Une seule session à la fois (un seul écran, une seule projection).
    busy: AtomicBool,
}

async fn start(
    identity: Arc<DeviceIdentity>,
    config: HostConfig,
    delegate: Arc<dyn HostDelegate>,
    clipboard: Option<Arc<dyn ClipboardProvider>>,
) -> Result<Arc<HostService>, MobileError> {
    let enrollment_path = PathBuf::from(&config.enrollment_path);
    let mut enrollment = Enrollment::load(&enrollment_path).map_err(|e| MobileError::App {
        detail: format!("enrôlement {} : {e}", enrollment_path.display()),
    })?;
    let server = match (&config.server, &enrollment) {
        (Some(s), _) => s.clone(),
        (None, Some(e)) => ServerConfig {
            address: e.server.clone(),
            pin: e.server_pin.clone(),
        },
        (None, None) => return Err(MobileError::invalid("aucun serveur configuré")),
    };
    let pin = server.pin()?;
    if let Some(e) = &enrollment
        && e.server_pin != pin.to_string()
    {
        return Err(MobileError::invalid(format!(
            "cet appareil est enrôlé auprès d'un autre serveur ({})",
            e.server
        )));
    }
    let options = RegisterOptions {
        accept_direct: true,
        relay_only: config.relay_only,
    };
    let addr = server.resolve().await?;
    let mut rv = RendezvousClient::register_with(addr, pin, &identity, options)
        .await
        .map_err(|e| MobileError::network(format!("connexion au serveur : {e}")))?;

    if let Some(token) = config.enroll_token.as_deref().filter(|t| !t.is_empty()) {
        if enrollment.is_some() {
            return Err(MobileError::invalid(
                "cet appareil est déjà enrôlé : supprimez l'enrôlement pour le réenrôler",
            ));
        }
        let name = match config.name.trim() {
            "" => identity.device_id().to_string(),
            n => n.to_string(),
        };
        let r = rv
            .enroll(token.trim(), &name)
            .await
            .map_err(|e| MobileError::refused(format!("enrôlement : {e}")))?;
        let e = Enrollment {
            ticket_key: r
                .ticket_public_key
                .as_slice()
                .try_into()
                .map_err(|_| MobileError::network("clé de tickets invalide"))?,
            server: server.address.trim().to_string(),
            server_pin: pin.to_string(),
            entity_name: r.entity_name,
            fleet_name: r.fleet_name,
        };
        e.save(&enrollment_path).map_err(|err| MobileError::App {
            detail: format!("enrôlement {} : {err}", enrollment_path.display()),
        })?;
        enrollment = Some(e);
    }

    let (stop, stop_rx) = watch::channel(false);
    let frames = Arc::new(FrameQueue::default());
    let service = Arc::new(HostService {
        device_id: identity.device_id().to_string(),
        enrollment: enrollment.as_ref().map(|e| EnrollmentInfo {
            server: e.server.clone(),
            entity_name: e.entity_name.clone(),
            fleet_name: e.fleet_name.clone(),
        }),
        frames: frames.clone(),
        stop,
    });
    let ctx = Arc::new(Ctx {
        identity,
        enrollment,
        delegate,
        clipboard,
        files_dir: config.files_dir.map(PathBuf::from),
        frames,
        busy: AtomicBool::new(false),
    });
    tokio::spawn(run(rv, server, pin, options, ctx, stop_rx));
    Ok(service)
}

/// Sert les connexions ; se réenregistre après une coupure (réseau mobile).
async fn run(
    mut rv: RendezvousClient,
    server: ServerConfig,
    pin: ServerPin,
    options: RegisterOptions,
    ctx: Arc<Ctx>,
    mut stop: watch::Receiver<bool>,
) {
    let mut backoff = Duration::from_secs(2);
    loop {
        ctx.delegate.on_status(HostStatus::Online {
            address: server.address.clone(),
        });
        let message = tokio::select! {
            r = serve(&mut rv, &ctx) => match r {
                Ok(()) => "serveur déconnecté".to_string(),
                Err(e) => e.to_string(),
            },
            _ = stop.wait_for(|s| *s) => break,
        };
        rv.close();
        tracing::warn!("rendezvous interrompu : {message}");
        // Reconnexion, de plus en plus espacée (au plus 1 min).
        rv = loop {
            ctx.delegate.on_status(HostStatus::Offline {
                message: message.clone(),
                retry_seconds: backoff.as_secs() as u32,
            });
            tokio::select! {
                _ = tokio::time::sleep(backoff) => {}
                _ = stop.wait_for(|s| *s) => {
                    ctx.delegate.on_status(HostStatus::Stopped);
                    return;
                }
            }
            backoff = (backoff * 2).min(Duration::from_secs(60));
            let attempt = async {
                let addr = server.resolve().await?;
                RendezvousClient::register_with(addr, pin, &ctx.identity, options)
                    .await
                    .map_err(MobileError::network)
            };
            match attempt.await {
                Ok(rv) => break rv,
                Err(e) => tracing::info!("reconnexion : {e}"),
            }
        };
        backoff = Duration::from_secs(2);
    }
    rv.close();
    ctx.frames.close();
    ctx.delegate.on_status(HostStatus::Stopped);
}

/// Règles de session selon la décision prise sur le ticket.
fn policy(ctx: &Arc<Ctx>, decision: Decision) -> Result<Policy, ticket::TicketError> {
    let prompt = || {
        let delegate = ctx.delegate.clone();
        Some(Arc::new(move |req: host::ConsentRequest| {
            let answer = delegate.consent(ConsentRequest {
                viewer_name: req.viewer_name,
                device_id: req.device_id,
                fingerprint: req.fingerprint,
                user_email: req.user_email,
                verification_code: req.verification_code,
                permissions: req
                    .requested
                    .names()
                    .into_iter()
                    .map(String::from)
                    .collect(),
            });
            match answer {
                ConsentAnswer::Deny => Consent::Deny,
                ConsentAnswer::ViewOnly => Consent::ViewOnly,
                ConsentAnswer::Control => Consent::Control,
            }
        }) as ConsentPrompt)
    };
    Ok(match decision {
        // Appareil non enrôlé : toujours l'utilisateur présent.
        Decision::AcceptUnmanaged => Policy {
            allowed: Permissions::ALL,
            consent: prompt(),
            user_email: None,
        },
        Decision::Accept(t) => Policy {
            allowed: Permissions::from_bits_truncate(t.permissions),
            consent: None,
            user_email: Some(t.user_email),
        },
        Decision::AcceptWithConsent(t) => Policy {
            allowed: Permissions::from_bits_truncate(t.permissions),
            consent: prompt(),
            user_email: Some(t.user_email),
        },
        Decision::Decline(e) => return Err(e),
    })
}

async fn serve(rv: &mut RendezvousClient, ctx: &Arc<Ctx>) -> Result<(), MobileError> {
    let mut offers: HashMap<Vec<u8>, (PublicIdentity, Policy)> = HashMap::new();
    while let Some(event) = rv.next_event().await.map_err(MobileError::network)? {
        match event {
            Event::Offer(offer) => {
                let requester = offer
                    .requester
                    .as_ref()
                    .and_then(|p| ident::from_proto(p).ok());
                let decision = requester.as_ref().map(|r| {
                    ticket::decide(
                        ctx.enrollment.as_ref(),
                        &offer.session_ticket,
                        ctx.identity.public(),
                        r,
                        ticket::unix_now(),
                    )
                });
                let accepted = match (requester, decision) {
                    (Some(r), Some(d)) if !ctx.busy.load(Ordering::Relaxed) => {
                        match policy(ctx, d) {
                            Ok(p) => Some((r, p)),
                            Err(e) => {
                                tracing::info!("demande de {} refusée : {e}", r.device_id());
                                None
                            }
                        }
                    }
                    (Some(r), _) => {
                        tracing::info!("demande de {} refusée : session en cours", r.device_id());
                        None
                    }
                    _ => None,
                };
                rv.answer(&offer, accepted.is_some())
                    .await
                    .map_err(MobileError::network)?;
                if let Some(a) = accepted {
                    offers.insert(offer.session_id.clone(), a);
                }
            }
            Event::Grant(grant) => {
                let Some((expected, policy)) = offers.remove(&grant.session_id) else {
                    continue;
                };
                if ctx.busy.swap(true, Ordering::AcqRel) {
                    continue;
                }
                let connector = rv.connector();
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    let peer_id = expected.device_id().to_string();
                    let r = session(&connector, &grant, &expected, policy, &ctx).await;
                    let message = match r {
                        Ok(()) => String::new(),
                        Err(e) => e.to_string(),
                    };
                    ctx.busy.store(false, Ordering::Release);
                    ctx.delegate
                        .on_status(HostStatus::SessionEnded { peer_id, message });
                });
            }
            Event::Rejected(_) => {}
        }
    }
    Ok(())
}

async fn session(
    connector: &creamote_net::rendezvous::Connector,
    grant: &RelayGrant,
    expected: &PublicIdentity,
    policy: Policy,
    ctx: &Arc<Ctx>,
) -> Result<(), MobileError> {
    // Connexion directe si possible, relay sinon.
    let stream = connector.host(grant).await.map_err(MobileError::network)?;
    let direct = stream.path() == PeerPath::Direct;
    let chan = SecureChannel::respond(stream, &ctx.identity)
        .await
        .map_err(MobileError::network)?;
    // Le serveur a annoncé une identité ; Noise prouve celle du pair réel.
    if chan.remote() != expected {
        return Err(MobileError::refused(
            "l'identité authentifiée ne correspond pas à celle annoncée par le serveur",
        ));
    }
    ctx.delegate.on_status(HostStatus::SessionStarted {
        peer_id: expected.device_id().to_string(),
        user_email: policy.user_email.clone(),
        direct,
        verification_code: chan.verification_code().to_string(),
    });
    let sharing = Sharing {
        clipboard: ctx
            .clipboard
            .clone()
            .map(|c| Box::new(AppClipboard(c)) as _),
        files: ctx.files_dir.clone().map(|dest| FilesConfig {
            dest,
            policy: AcceptPolicy::AcceptAll,
            events: None,
        }),
    };
    let (tx, rx) = chan.split();
    host::serve_with(tx, rx, policy, media(ctx), sharing)
        .await
        .map(|_| ())
        .map_err(|e| MobileError::Network {
            detail: e.to_string(),
        })
}

fn display_info(d: &Display) -> DisplayInfo {
    DisplayInfo {
        id: d.id,
        name: d.name.clone(),
        x: 0,
        y: 0,
        width: d.width,
        height: d.height,
        scale: 1.0,
        primary: true,
    }
}

fn media(ctx: &Arc<Ctx>) -> Media {
    let displays = {
        let delegate = ctx.delegate.clone();
        Arc::new(move || Ok(vec![display_info(&delegate.screen())]))
    };
    let source = {
        let (delegate, frames) = (ctx.delegate.clone(), ctx.frames.clone());
        Arc::new(move |req: SourceRequest| {
            PushedSource::open(delegate.clone(), frames.clone(), req)
                .map(|s| Box::new(s) as Box<dyn EncodedSource>)
        })
    };
    let injector = {
        let delegate = ctx.delegate.clone();
        Arc::new(move |_: DisplayInfo| {
            Ok(Box::new(DelegateInput {
                delegate: delegate.clone(),
                pressed: BTreeSet::new(),
                buttons: 0,
            }) as Box<dyn InputSink>)
        })
    };
    Media::encoded(displays, source, injector)
}

/// Image poussée par l'app.
struct Pushed {
    frame: EncodedFrame,
    width: u32,
    height: u32,
}

/// Images encodées en attente d'envoi. Si l'envoi prend du retard (réseau
/// saturé, contrôle de flux), la file est vidée et l'on attend la prochaine
/// image clé, demandée à l'encodeur : une image P ne peut pas être sautée
/// sans corrompre la suite.
#[derive(Default)]
struct FrameQueue {
    state: Mutex<QueueState>,
    ready: Condvar,
    /// Image clé à demander à l'encodeur.
    keyframe_wanted: AtomicBool,
}

#[derive(Default)]
struct QueueState {
    open: bool,
    frames: VecDeque<Pushed>,
    need_keyframe: bool,
}

/// Images en attente au-delà desquelles la file est vidée.
const MAX_QUEUED: usize = 4;

impl FrameQueue {
    fn reopen(&self) {
        let mut s = self.state.lock().expect("verrou sain");
        *s = QueueState {
            open: true,
            frames: VecDeque::new(),
            need_keyframe: true,
        };
    }

    fn close(&self) {
        let mut s = self.state.lock().expect("verrou sain");
        s.open = false;
        s.frames.clear();
        self.ready.notify_all();
    }

    fn push(&self, p: Pushed) {
        let mut s = self.state.lock().expect("verrou sain");
        if !s.open {
            return;
        }
        if p.frame.keyframe {
            s.need_keyframe = false;
            // Une image clé rend les précédentes inutiles.
            s.frames.clear();
        } else if s.need_keyframe {
            return;
        } else if s.frames.len() >= MAX_QUEUED {
            tracing::debug!("file vidéo pleine : attente d'une image clé");
            s.frames.clear();
            s.need_keyframe = true;
            // Demandée par le thread de diffusion (`next`), hors du verrou.
            self.keyframe_wanted.store(true, Ordering::Relaxed);
            return;
        }
        s.frames.push_back(p);
        self.ready.notify_one();
    }

    fn pop(&self, timeout: Duration) -> Result<Option<Pushed>, String> {
        let s = self.state.lock().expect("verrou sain");
        let (mut s, _) = self
            .ready
            .wait_timeout_while(s, timeout, |s| s.open && s.frames.is_empty())
            .expect("verrou sain");
        if !s.open {
            return Err("diffusion arrêtée par l'appareil".into());
        }
        Ok(s.frames.pop_front())
    }
}

/// Flux alimenté par l'encodeur MediaCodec de l'app.
struct PushedSource {
    delegate: Arc<dyn HostDelegate>,
    frames: Arc<FrameQueue>,
    display: DisplayInfo,
    name: String,
    bitrate: u32,
    size: (u32, u32),
}

impl PushedSource {
    fn open(
        delegate: Arc<dyn HostDelegate>,
        frames: Arc<FrameQueue>,
        req: SourceRequest,
    ) -> Result<Self, String> {
        let display = display_info(&delegate.screen());
        frames.reopen();
        let info = delegate
            .start_stream(StreamRequest {
                fps: req.fps,
                bitrate_bps: req.bitrate_bps,
            })
            .map_err(|e| e.to_string())?;
        Ok(Self {
            size: (display.width, display.height),
            display,
            name: info.encoder,
            bitrate: info.bitrate_bps,
            delegate,
            frames,
        })
    }
}

impl EncodedSource for PushedSource {
    fn display(&self) -> DisplayInfo {
        self.display.clone()
    }
    fn name(&self) -> String {
        self.name.clone()
    }
    fn size(&self) -> (u32, u32) {
        self.size
    }
    fn bitrate(&self) -> u32 {
        self.bitrate
    }
    fn next(&mut self, timeout: Duration) -> Result<Option<EncodedFrame>, String> {
        if self.frames.keyframe_wanted.swap(false, Ordering::Relaxed) {
            self.delegate.request_keyframe();
        }
        Ok(self.frames.pop(timeout)?.map(|p| {
            self.size = (p.width, p.height);
            p.frame
        }))
    }
    fn request_keyframe(&mut self) {
        self.delegate.request_keyframe();
    }
    fn set_bitrate(&mut self, bps: u32) {
        self.bitrate = bps;
        self.delegate.set_bitrate(bps);
    }
}

impl Drop for PushedSource {
    fn drop(&mut self) {
        self.frames.close();
        self.delegate.stop_stream();
    }
}

/// Entrées du viewer remises à l'app (AccessibilityService ou API
/// constructeur), avec suivi de ce qui est enfoncé.
struct DelegateInput {
    delegate: Arc<dyn HostDelegate>,
    pressed: BTreeSet<u32>,
    buttons: u32,
}

impl InputSink for DelegateInput {
    fn key(&mut self, hid: u32, pressed: bool) {
        if !pressed && !self.pressed.remove(&hid) {
            return;
        }
        if pressed {
            self.pressed.insert(hid);
        }
        self.delegate.key(hid, android_keycode(hid), pressed);
    }

    fn pointer(&mut self, p: &Pointer) {
        if !(p.x.is_finite() && p.y.is_finite()) {
            return;
        }
        let finite = |v: f32| {
            if v.is_finite() {
                v.clamp(-50.0, 50.0)
            } else {
                0.0
            }
        };
        self.buttons = p.buttons & Button::ALL.iter().fold(0, |m, b| m | b.mask());
        self.delegate.pointer(
            p.x.clamp(0.0, 1.0),
            p.y.clamp(0.0, 1.0),
            self.buttons,
            finite(p.wheel_dx),
            finite(p.wheel_dy),
        );
    }
}

impl Drop for DelegateInput {
    fn drop(&mut self) {
        if !self.pressed.is_empty() || self.buttons != 0 {
            self.delegate.release_all();
        }
    }
}
