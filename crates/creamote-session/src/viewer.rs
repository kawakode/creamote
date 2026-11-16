//! Côté viewer d'une session.

use creamote_proto::permissions::Permissions;
use creamote_proto::session::v1 as pb;
use pb::session_message::Kind;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use creamote_net::secure::{SecureReceiver, SecureSender};
use creamote_transfer::files::FilesHandle;

use crate::sharing::{Active, Sharing};

use crate::{
    DEFAULT_FPS, EndReason, Reassembler, Result, SessionError, VideoFrame, from_proto, recv, send,
    to_proto,
};

#[derive(Debug, Clone)]
pub struct Options {
    /// Nom affiché chez l'utilisateur du host (non vérifié).
    pub display_name: String,
    pub requested: Permissions,
    pub max_fps: u32,
    /// Débit souhaité ; 0 : choix du host.
    pub bitrate_bps: u32,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            display_name: String::new(),
            requested: Permissions::VIEW | Permissions::CONTROL,
            max_fps: DEFAULT_FPS,
            bitrate_bps: 0,
        }
    }
}

/// Événements reçus du host.
#[derive(Debug, Clone)]
pub enum Event {
    /// Session acceptée (après consentement éventuel).
    Accepted {
        granted: Permissions,
        displays: Vec<pb::Display>,
    },
    /// Paramètres du flux vidéo (au début et à chaque changement de taille).
    Video(pb::VideoConfig),
    /// Image complète ; à acquitter avec [`Handle::ack`] une fois décodée.
    Frame(VideoFrame),
    /// Transfert de fichiers accordé : envois vers le host et réponses aux
    /// propositions (voir [`crate::FilesConfig::events`]).
    Files(FilesHandle),
    /// Fin de session annoncée par le host.
    Ended { reason: EndReason, message: String },
}

/// Commandes vers le host ; clonable, utilisable depuis n'importe où.
#[derive(Clone)]
pub struct Handle {
    tx: mpsc::Sender<Kind>,
}

impl Handle {
    async fn push(&self, kind: Kind) -> Result<()> {
        self.tx.send(kind).await.map_err(|_| SessionError::Closed)
    }

    pub async fn key(&self, hid_usage: u32, pressed: bool) -> Result<()> {
        self.push(Kind::Key(pb::KeyEvent {
            hid_usage,
            pressed,
            modifiers: 0,
        }))
        .await
    }

    pub async fn pointer(&self, p: pb::PointerEvent) -> Result<()> {
        self.push(Kind::Pointer(p)).await
    }

    pub async fn ack(&self, frame_id: u64) -> Result<()> {
        self.push(Kind::FrameAck(pb::FrameAck { frame_id })).await
    }

    pub async fn request_keyframe(&self) -> Result<()> {
        self.push(Kind::KeyframeRequest(pb::KeyframeRequest {}))
            .await
    }

    /// Choisit l'écran diffusé (et redémarre le flux).
    pub async fn select_display(
        &self,
        display_id: u32,
        max_fps: u32,
        bitrate_bps: u32,
    ) -> Result<()> {
        self.push(Kind::VideoConfig(pb::VideoConfig {
            display_id,
            codec: pb::video_config::Codec::H264 as i32,
            max_fps,
            target_bitrate_bps: bitrate_bps,
            ..Default::default()
        }))
        .await
    }

    /// Termine la session proprement.
    pub async fn close(&self) {
        let _ = self
            .push(Kind::End(pb::SessionEnd {
                reason: EndReason::Closed as i32,
                message: String::new(),
            }))
            .await;
    }
}

/// Ouvre la session sur un canal déjà authentifié : envoie `Hello`, attend
/// l'acceptation, demande le flux de l'écran principal, puis relaie les
/// événements jusqu'à la fin.
pub fn start<R, W>(
    tx: SecureSender<W>,
    rx: SecureReceiver<R>,
    opts: Options,
) -> (Handle, mpsc::Receiver<Event>)
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    start_with(tx, rx, opts, Sharing::default())
}

/// Comme [`start`], avec le presse-papier et les fichiers offerts par ce
/// côté ; les permissions correspondantes sont ajoutées à la demande.
pub fn start_with<R, W>(
    mut tx: SecureSender<W>,
    mut rx: SecureReceiver<R>,
    mut opts: Options,
    sharing: Sharing,
) -> (Handle, mpsc::Receiver<Event>)
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    opts.requested = opts.requested | sharing.permissions();
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<Kind>(256);
    let (ev_tx, ev_rx) = mpsc::channel::<Event>(16);
    let handle = Handle { tx: cmd_tx };

    let hello = Kind::Hello(pb::Hello {
        display_name: opts.display_name.clone(),
        requested: Some(to_proto(opts.requested)),
    });
    tokio::spawn(async move {
        if send(&mut tx, hello).await.is_err() {
            return;
        }
        while let Some(kind) = cmd_rx.recv().await {
            let last = matches!(kind, Kind::End(_));
            if send(&mut tx, kind).await.is_err() || last {
                break;
            }
        }
        let _ = tx.close().await;
    });

    let commands = handle.clone();
    tokio::spawn(async move {
        let r = read_loop(&mut rx, &commands, &ev_tx, &opts, sharing).await;
        let (reason, message) = match r {
            Ok(Some(end)) => end,
            Ok(None) => (EndReason::Closed, "le host a fermé la session".into()),
            Err(e) => (EndReason::Error, e.to_string()),
        };
        let _ = ev_tx.send(Event::Ended { reason, message }).await;
    });
    (handle, ev_rx)
}

async fn read_loop<R: AsyncRead + Unpin>(
    rx: &mut SecureReceiver<R>,
    commands: &Handle,
    events: &mpsc::Sender<Event>,
    opts: &Options,
    sharing: Sharing,
) -> Result<Option<(EndReason, String)>> {
    let mut frames = Reassembler::default();
    let mut sharing = Some(sharing);
    let mut active: Option<Active> = None;
    // Annoncé juste après `Accepted`.
    let mut announce = None;
    while let Some(kind) = recv(rx).await? {
        let kind = match &mut active {
            Some(a) => match a.handle(kind).await {
                Some(k) => k,
                None => continue,
            },
            None => kind,
        };
        let ev = match kind {
            Kind::HelloAck(ack) => {
                let granted = from_proto(ack.granted.as_ref());
                if let Some(s) = sharing.take() {
                    let a = Active::start(s, granted, commands.tx.clone());
                    announce = a.files();
                    active = Some(a);
                }
                let display = ack
                    .displays
                    .iter()
                    .find(|d| d.primary)
                    .or(ack.displays.first())
                    .map_or(0, |d| d.id);
                commands
                    .select_display(display, opts.max_fps, opts.bitrate_bps)
                    .await?;
                Event::Accepted {
                    granted,
                    displays: ack.displays,
                }
            }
            Kind::VideoConfig(c) => Event::Video(c),
            Kind::VideoChunk(c) => match frames.push(c)? {
                Some(f) => Event::Frame(f),
                None => continue,
            },
            Kind::End(e) => {
                let reason = EndReason::try_from(e.reason).unwrap_or(EndReason::Unspecified);
                return Ok(Some((reason, e.message)));
            }
            _ => continue,
        };
        let files = announce.take().map(Event::Files);
        if events.send(ev).await.is_err()
            || match files {
                Some(f) => events.send(f).await.is_err(),
                None => false,
            }
        {
            // Plus personne n'écoute : fin de session.
            commands.close().await;
            return Ok(None);
        }
    }
    Ok(None)
}
