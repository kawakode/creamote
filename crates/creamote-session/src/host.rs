//! Côté host d'une session.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, mpsc as std_mpsc};
use std::time::{Duration, Instant};

use creamote_capture::{Capturer, DisplayInfo, Frame};
use creamote_codec::{EncoderConfig, Preference, VideoEncoder};
use creamote_input::{Injector, Pointer};
use creamote_net::secure::{SecureReceiver, SecureSender};
use creamote_proto::permissions::Permissions;
use creamote_proto::session::v1 as pb;
use pb::session_message::Kind;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use crate::rate::RateController;
use crate::sharing::{Active, Sharing};
use crate::{
    DEFAULT_FPS, EndReason, MAX_FRAMES_IN_FLIGHT, Result, SessionError, chunks, from_proto,
    intersect, recv, send, to_proto,
};

/// Délai laissé à l'utilisateur présent pour répondre.
pub const CONSENT_TIMEOUT: Duration = Duration::from_secs(30);
/// Délai pour recevoir le `Hello` du viewer.
const HELLO_TIMEOUT: Duration = Duration::from_secs(30);
/// Permissions que ce host sait honorer sans configuration ; presse-papier
/// et fichiers s'y ajoutent selon le [`Sharing`] passé à [`serve_with`].
pub const SUPPORTED: Permissions = Permissions::VIEW.union(Permissions::CONTROL);

/// Ce que l'utilisateur présent a répondu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consent {
    Deny,
    ViewOnly,
    Control,
}

/// Demande présentée à l'utilisateur présent.
#[derive(Debug, Clone)]
pub struct ConsentRequest {
    /// Nom annoncé par le viewer (non vérifié).
    pub viewer_name: String,
    /// ID et empreinte de l'appareil, prouvés par le handshake Noise.
    pub device_id: String,
    pub fingerprint: String,
    /// Compte de l'utilisateur, garanti par le ticket signé du serveur.
    pub user_email: Option<String>,
    /// Code à comparer de vive voix avec celui affiché chez le viewer.
    pub verification_code: String,
    pub requested: Permissions,
}

/// Demande bloquante (boîte de dialogue native) ; exécutée hors du runtime.
pub type ConsentPrompt = Arc<dyn Fn(ConsentRequest) -> Consent + Send + Sync>;

/// Règles appliquées à une session.
pub struct Policy {
    /// Permissions maximales : celles du ticket, ou toutes (host non géré).
    pub allowed: Permissions,
    /// `None` : session sans surveillance (ticket `unattended`, ou mode
    /// développement explicite).
    pub consent: Option<ConsentPrompt>,
    pub user_email: Option<String>,
}

/// Destination des entrées du viewer.
pub trait InputSink {
    fn key(&mut self, hid_usage: u32, pressed: bool);
    fn pointer(&mut self, p: &Pointer);
}

impl InputSink for Injector {
    fn key(&mut self, hid_usage: u32, pressed: bool) {
        if let Err(e) = Injector::key(self, hid_usage, pressed) {
            tracing::debug!("injection clavier : {e}");
        }
    }
    fn pointer(&mut self, p: &Pointer) {
        if let Err(e) = Injector::pointer(self, p) {
            tracing::debug!("injection souris : {e}");
        }
    }
}

type DisplaysFn = dyn Fn() -> creamote_capture::Result<Vec<DisplayInfo>> + Send + Sync;
type CapturerFn = dyn Fn(Option<u32>) -> creamote_capture::Result<Box<dyn Capturer>> + Send + Sync;
type InjectorFn = dyn Fn(DisplayInfo) -> Result<Box<dyn InputSink>, String> + Send + Sync;

/// Sources et puits du host ; remplaçables pour les tests.
#[derive(Clone)]
pub struct Media {
    pub displays: Arc<DisplaysFn>,
    pub capturer: Arc<CapturerFn>,
    pub injector: Arc<InjectorFn>,
    pub encoder: Preference,
}

impl Media {
    /// Capture, encodage et injection natifs de l'OS.
    pub fn native(encoder: Preference) -> Self {
        Self {
            displays: Arc::new(creamote_capture::displays),
            capturer: Arc::new(creamote_capture::open),
            injector: Arc::new(|d| {
                Injector::open(d)
                    .map(|i| Box::new(i) as Box<dyn InputSink>)
                    .map_err(|e| e.to_string())
            }),
            encoder,
        }
    }
}

fn end(reason: EndReason, message: impl Into<String>) -> Kind {
    Kind::End(pb::SessionEnd {
        reason: reason as i32,
        message: message.into(),
    })
}

fn display_proto(d: &DisplayInfo) -> pb::Display {
    pb::Display {
        id: d.id,
        name: d.name.clone(),
        width: d.width,
        height: d.height,
        scale: d.scale,
        primary: d.primary,
    }
}

/// Bilan d'une session terminée.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub granted: Permissions,
}

/// Mène une session côté host jusqu'à sa fin (sans presse-papier ni
/// fichiers).
pub async fn serve<R, W>(
    tx: SecureSender<W>,
    rx: SecureReceiver<R>,
    policy: Policy,
    media: Media,
) -> Result<Summary>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    serve_with(tx, rx, policy, media, Sharing::default()).await
}

/// Comme [`serve`], avec le presse-papier et les fichiers que ce host offre.
pub async fn serve_with<R, W>(
    mut tx: SecureSender<W>,
    mut rx: SecureReceiver<R>,
    policy: Policy,
    media: Media,
    sharing: Sharing,
) -> Result<Summary>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let hello = match tokio::time::timeout(HELLO_TIMEOUT, recv(&mut rx)).await {
        Ok(Ok(Some(Kind::Hello(h)))) => h,
        Ok(Ok(None)) => return Err(SessionError::Closed),
        Ok(Err(e)) => return Err(e),
        Ok(Ok(Some(_))) => return Err(SessionError::Protocol("Hello attendu")),
        Err(_) => return Err(SessionError::Protocol("pas de Hello du viewer")),
    };
    let requested = from_proto(hello.requested.as_ref());
    let supported = SUPPORTED | sharing.permissions();
    let mut granted = intersect(intersect(policy.allowed, requested), supported);
    if !granted.contains(Permissions::VIEW) {
        send(
            &mut tx,
            end(EndReason::Forbidden, "affichage de l'écran non autorisé"),
        )
        .await?;
        return Err(SessionError::Ended {
            reason: EndReason::Forbidden,
            message: String::new(),
        });
    }

    if let Some(prompt) = policy.consent.clone() {
        let req = ConsentRequest {
            viewer_name: hello.display_name.chars().take(64).collect(),
            device_id: rx.remote().device_id().to_string(),
            fingerprint: rx.remote().fingerprint(),
            user_email: policy.user_email.clone(),
            verification_code: rx.verification_code().to_string(),
            requested: granted,
        };
        let answer = tokio::time::timeout(
            CONSENT_TIMEOUT,
            tokio::task::spawn_blocking(move || prompt(req)),
        )
        .await;
        let (reason, msg) = match answer {
            Ok(Ok(Consent::Control)) => (None, ""),
            Ok(Ok(Consent::ViewOnly)) => {
                granted = Permissions::VIEW;
                (None, "")
            }
            Ok(Ok(Consent::Deny)) | Ok(Err(_)) => (
                Some(EndReason::Declined),
                "l'utilisateur du poste a refusé la connexion",
            ),
            Err(_) => (
                Some(EndReason::ConsentTimeout),
                "pas de réponse de l'utilisateur du poste",
            ),
        };
        if let Some(reason) = reason {
            send(&mut tx, end(reason, msg)).await?;
            return Err(SessionError::Ended {
                reason,
                message: msg.into(),
            });
        }
    }

    let displays = {
        let f = media.displays.clone();
        tokio::task::spawn_blocking(move || f())
            .await
            .map_err(|_| SessionError::Protocol("énumération des écrans interrompue"))?
    };
    let displays = match displays {
        Ok(d) => d,
        Err(e) => {
            send(&mut tx, end(EndReason::Error, e.to_string())).await?;
            return Err(SessionError::Ended {
                reason: EndReason::Error,
                message: e.to_string(),
            });
        }
    };
    send(
        &mut tx,
        Kind::HelloAck(pb::HelloAck {
            granted: Some(to_proto(granted)),
            displays: displays.iter().map(display_proto).collect(),
        }),
    )
    .await?;
    tracing::info!("session ouverte, permissions {granted:?}");

    // Tâche d'émission : tout message sortant passe par ce canal.
    let (out_tx, mut out_rx) = mpsc::channel::<Kind>(64);
    let writer = tokio::spawn(async move {
        while let Some(kind) = out_rx.recv().await {
            let last = matches!(kind, Kind::End(_));
            if send(&mut tx, kind).await.is_err() || last {
                break;
            }
        }
        let _ = tx.close().await;
    });

    let control = granted.contains(Permissions::CONTROL);
    let display_watch = tokio::spawn(watch_displays(
        media.clone(),
        displays.clone(),
        out_tx.clone(),
    ));
    let mut active = Active::start(sharing, granted, out_tx.clone());
    let mut stream: Option<Stream> = None;
    let result = loop {
        let msg = match recv(&mut rx).await {
            Ok(Some(m)) => m,
            Ok(None) => break Ok(()),
            Err(e) => break Err(e),
        };
        let Some(msg) = active.handle(msg).await else {
            continue;
        };
        match msg {
            Kind::VideoConfig(req) => {
                if let Some(s) = stream.take() {
                    s.stop();
                }
                stream = Some(Stream::start(req, &media, out_tx.clone()));
            }
            Kind::Key(k) if control => {
                if let Some(s) = &stream {
                    let _ = s.input.send(Input::Key(k.hid_usage, k.pressed));
                }
            }
            Kind::Pointer(p) if control => {
                if let Some(s) = &stream {
                    let _ = s.input.send(Input::Pointer(Pointer {
                        x: p.x,
                        y: p.y,
                        buttons: p.buttons,
                        wheel_dx: p.wheel_dx,
                        wheel_dy: p.wheel_dy,
                    }));
                }
            }
            Kind::FrameAck(a) => {
                if let Some(s) = &stream {
                    s.ctl.acked.fetch_max(a.frame_id, Ordering::Relaxed);
                    let mut acks = s.ctl.acks.lock().expect("verrou sain");
                    if acks.len() < 256 {
                        acks.push((a.frame_id, Instant::now()));
                    }
                }
            }
            Kind::KeyframeRequest(_) => {
                if let Some(s) = &stream {
                    s.ctl.keyframe.store(true, Ordering::Relaxed);
                }
            }
            Kind::End(_) => break Ok(()),
            _ => {}
        }
    };
    if let Some(s) = stream.take() {
        s.stop();
    }
    display_watch.abort();
    drop(active);
    drop(out_tx);
    let _ = writer.await;
    result.map(|()| Summary { granted })
}

/// Intervalle de vérification de la liste des écrans.
const DISPLAYS_POLL: Duration = Duration::from_secs(2);

/// Signale au viewer les changements de la liste des écrans.
async fn watch_displays(media: Media, mut known: Vec<DisplayInfo>, out: mpsc::Sender<Kind>) {
    loop {
        tokio::time::sleep(DISPLAYS_POLL).await;
        let f = media.displays.clone();
        let Ok(Ok(now)) = tokio::task::spawn_blocking(move || f()).await else {
            continue;
        };
        if now != known {
            tracing::info!(count = now.len(), "configuration des écrans modifiée");
            let msg = Kind::DisplayList(pb::DisplayList {
                displays: now.iter().map(display_proto).collect(),
            });
            if out.send(msg).await.is_err() {
                return;
            }
            known = now;
        }
    }
}

enum Input {
    Key(u32, bool),
    Pointer(Pointer),
}

#[derive(Default)]
struct StreamCtl {
    stop: AtomicBool,
    acked: AtomicU64,
    keyframe: AtomicBool,
    /// Accusés reçus (image, instant), pour le débit adaptatif.
    acks: std::sync::Mutex<Vec<(u64, Instant)>>,
}

/// Diffusion d'un écran : un thread de capture/encodage et un thread
/// d'injection, propriétaires de leurs objets natifs.
struct Stream {
    ctl: Arc<StreamCtl>,
    input: std_mpsc::Sender<Input>,
}

impl Stream {
    fn start(req: pb::VideoConfig, media: &Media, out: mpsc::Sender<Kind>) -> Self {
        let ctl = Arc::new(StreamCtl::default());
        let (input, input_rx) = std_mpsc::channel();
        let (display_tx, display_rx) = std_mpsc::channel();
        {
            let (ctl, media) = (ctl.clone(), media.clone());
            std::thread::Builder::new()
                .name("creamote-video".into())
                .spawn(move || {
                    if let Err(msg) = video_loop(&req, &media, &ctl, &out, display_tx) {
                        tracing::warn!("diffusion interrompue : {msg}");
                        let _ = out.blocking_send(end(EndReason::Error, msg));
                    }
                })
                .expect("thread vidéo");
        }
        {
            let media = media.clone();
            std::thread::Builder::new()
                .name("creamote-input".into())
                .spawn(move || input_loop(&media, display_rx, input_rx))
                .expect("thread d'entrées");
        }
        Self { ctl, input }
    }

    fn stop(self) {
        self.ctl.stop.store(true, Ordering::Relaxed);
    }
}

fn input_loop(
    media: &Media,
    display: std_mpsc::Receiver<DisplayInfo>,
    events: std_mpsc::Receiver<Input>,
) {
    // L'écran est connu une fois la capture ouverte.
    let Ok(mut current) = display.recv() else {
        return;
    };
    let mut sink: Option<Box<dyn InputSink>> = None;
    let mut failed = false;
    while let Ok(ev) = events.recv() {
        // La capture a basculé sur un autre écran : nouvelle cible.
        while let Ok(d) = display.try_recv() {
            current = d;
            sink = None;
            failed = false;
        }
        if sink.is_none() && !failed {
            match (media.injector)(current.clone()) {
                Ok(s) => sink = Some(s),
                Err(e) => {
                    tracing::warn!("injection d'entrées impossible : {e}");
                    failed = true;
                }
            }
        }
        if let Some(s) = &mut sink {
            match ev {
                Input::Key(hid, pressed) => s.key(hid, pressed),
                Input::Pointer(p) => s.pointer(&p),
            }
        }
    }
    // `Injector` relâche touches et boutons à sa destruction.
}

fn video_loop(
    req: &pb::VideoConfig,
    media: &Media,
    ctl: &StreamCtl,
    out: &mpsc::Sender<Kind>,
    display_tx: std_mpsc::Sender<DisplayInfo>,
) -> Result<(), String> {
    // Écran inconnu (configuration changée) : l'écran principal.
    let mut capturer = (media.capturer)(Some(req.display_id))
        .or_else(|_| (media.capturer)(None))
        .map_err(|e| e.to_string())?;
    let mut display = capturer.display().clone();
    let _ = display_tx.send(display.clone());
    let mut reopened: Option<Instant> = None;
    let fps = match req.max_fps {
        0 => DEFAULT_FPS,
        f => f.clamp(1, 60),
    };
    let interval = Duration::from_secs(1) / fps;
    let start = Instant::now();
    let mut encoder: Option<creamote_codec::Chain> = None;
    let mut rate: Option<(RateController, pb::VideoConfig)> = None;
    let mut last: Option<Frame> = None;
    let mut sent: u64 = 0;
    let mut last_sent = start.checked_sub(interval).unwrap_or(start);

    while !ctl.stop.load(Ordering::Relaxed) {
        if sent.saturating_sub(ctl.acked.load(Ordering::Relaxed)) >= MAX_FRAMES_IN_FLIGHT {
            std::thread::sleep(Duration::from_millis(2));
            continue;
        }
        let wait = interval.saturating_sub(last_sent.elapsed());
        if !wait.is_zero() {
            std::thread::sleep(wait);
        }
        let mut force = ctl.keyframe.swap(false, Ordering::Relaxed);
        let captured = match capturer.next_frame(Duration::from_millis(100)) {
            Ok(c) => c,
            // Écran débranché ou reconfiguré : on rouvre l'écran principal
            // (une fois ; un second échec rapproché met fin au flux).
            Err(e) if reopened.is_none_or(|t| t.elapsed() > Duration::from_secs(5)) => {
                tracing::info!("capture interrompue ({e}), bascule sur l'écran principal");
                capturer = (media.capturer)(None).map_err(|e| e.to_string())?;
                display = capturer.display().clone();
                let _ = display_tx.send(display.clone());
                reopened = Some(Instant::now());
                encoder = None;
                last = None;
                continue;
            }
            Err(e) => return Err(e.to_string()),
        };
        match captured {
            Some(f) => last = Some(f),
            // Écran inchangé : on ne réencode la dernière image que si le
            // viewer a demandé une image clé.
            None if force && last.is_some() => {}
            None => {
                if force {
                    ctl.keyframe.store(true, Ordering::Relaxed);
                }
                continue;
            }
        }
        let Some(frame) = &last else { continue };
        let (w, h) = creamote_codec::yuv::even_dims(frame.width, frame.height);
        if w < 2 || h < 2 {
            continue;
        }
        if encoder
            .as_ref()
            .is_none_or(|e| (e.config().width, e.config().height) != (w, h))
        {
            let mut cfg = EncoderConfig::for_size(w, h, fps);
            if req.target_bitrate_bps > 0 {
                cfg.bitrate_bps = req.target_bitrate_bps.clamp(200_000, 50_000_000);
            }
            let e = creamote_codec::open_h264(cfg, media.encoder).map_err(|e| e.to_string())?;
            let config = pb::VideoConfig {
                display_id: display.id,
                codec: pb::video_config::Codec::H264 as i32,
                width: w,
                height: h,
                target_bitrate_bps: cfg.bitrate_bps,
                max_fps: fps,
                encoder: e.name(),
            };
            if out
                .blocking_send(Kind::VideoConfig(config.clone()))
                .is_err()
            {
                return Ok(());
            }
            ctl.acks.lock().expect("verrou sain").clear();
            rate = Some((RateController::new(cfg.bitrate_bps, Instant::now()), config));
            encoder = Some(e);
            force = true;
        }
        let Some(enc) = encoder.as_mut() else {
            continue;
        };
        if let Some((rc, config)) = &mut rate {
            for (id, at) in ctl.acks.lock().expect("verrou sain").drain(..) {
                rc.on_ack(id, at);
            }
            if let Some(bps) = rc.tick(Instant::now()) {
                tracing::info!(kbit_s = bps / 1000, "débit adaptatif");
                enc.set_bitrate(bps);
                config.target_bitrate_bps = bps;
                // Informatif pour le viewer (affichage du débit).
                if out
                    .blocking_send(Kind::VideoConfig(config.clone()))
                    .is_err()
                {
                    return Ok(());
                }
            }
        }
        let encoded = enc.encode(frame, force).map_err(|e| e.to_string())?;
        last_sent = Instant::now();
        for e in encoded {
            sent += 1;
            if let Some((rc, _)) = &mut rate {
                rc.on_sent(sent, e.data.len(), last_sent);
            }
            let ts = e.captured_at.saturating_duration_since(start).as_micros() as u64;
            for c in chunks(display.id, sent, e.keyframe, ts, &e.data) {
                if out.blocking_send(Kind::VideoChunk(c)).is_err() {
                    return Ok(());
                }
            }
        }
    }
    Ok(())
}
