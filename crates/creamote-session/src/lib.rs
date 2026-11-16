//! Session de contrôle à distance au-dessus d'un canal chiffré Noise.
//!
//! - [`host`] : répond au viewer, obtient au besoin le consentement de
//!   l'utilisateur présent, diffuse l'écran (capture → H.264) et injecte les
//!   entrées autorisées.
//! - [`viewer`] : ouvre la session, reçoit la vidéo, envoie clavier et souris.
//! - [`sharing`] : presse-papier partagé et transfert de fichiers (M3),
//!   activés par chaque côté et accordés par le host.
//!
//! Flux : voir `proto/creamote/session.proto`. Les images encodées sont
//! découpées en [`VideoChunk`](creamote_proto::session::v1::VideoChunk) ; le
//! viewer accuse réception de chaque image décodée et le host n'en garde que
//! [`MAX_FRAMES_IN_FLIGHT`] en vol, ce qui borne la latence quand le réseau
//! sature.

use creamote_net::secure::{SecureReceiver, SecureSender};
use creamote_proto::permissions::Permissions;
use creamote_proto::session::v1 as pb;
use prost::Message;
use tokio::io::{AsyncRead, AsyncWrite};

pub mod host;
pub mod rate;
pub mod sharing;
pub mod viewer;

pub use creamote_transfer;
pub use sharing::{FilesConfig, Sharing};

pub use pb::session_end::Reason as EndReason;

/// Images envoyées et pas encore acquittées au-delà desquelles le host
/// attend avant d'en capturer une autre.
pub const MAX_FRAMES_IN_FLIGHT: u64 = 3;

/// Taille des morceaux d'image : sous la limite d'un message Noise
/// (65 519 octets) avec la marge de l'enveloppe protobuf.
pub const CHUNK_SIZE: usize = 60_000;

/// Cadence par défaut.
pub const DEFAULT_FPS: u32 = 30;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error(transparent)]
    Net(#[from] creamote_net::NetError),
    #[error("message de session illisible : {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("protocole de session : {0}")]
    Protocol(&'static str),
    #[error("session terminée : {reason:?} {message}")]
    Ended { reason: EndReason, message: String },
    #[error("le pair a fermé la connexion")]
    Closed,
}

pub type Result<T, E = SessionError> = std::result::Result<T, E>;

pub fn to_proto(p: Permissions) -> pb::Permissions {
    pb::Permissions {
        view_screen: p.contains(Permissions::VIEW),
        control_input: p.contains(Permissions::CONTROL),
        clipboard: p.contains(Permissions::CLIPBOARD),
        file_transfer: p.contains(Permissions::FILE_TRANSFER),
    }
}

pub fn from_proto(p: Option<&pb::Permissions>) -> Permissions {
    let Some(p) = p else {
        return Permissions::NONE;
    };
    [
        (p.view_screen, Permissions::VIEW),
        (p.control_input, Permissions::CONTROL),
        (p.clipboard, Permissions::CLIPBOARD),
        (p.file_transfer, Permissions::FILE_TRANSFER),
    ]
    .into_iter()
    .filter(|(on, _)| *on)
    .fold(Permissions::NONE, |acc, (_, p)| acc | p)
}

/// Permissions communes aux deux ensembles.
pub fn intersect(a: Permissions, b: Permissions) -> Permissions {
    Permissions::from_bits_truncate(a.bits() & b.bits())
}

pub(crate) async fn send<W: AsyncWrite + Unpin>(
    tx: &mut SecureSender<W>,
    kind: pb::session_message::Kind,
) -> Result<()> {
    let msg = pb::SessionMessage { kind: Some(kind) };
    tx.send(&msg.encode_to_vec()).await?;
    Ok(())
}

/// Prochain message ; `Ok(None)` en fin de flux, messages vides ignorés.
pub(crate) async fn recv<R: AsyncRead + Unpin>(
    rx: &mut SecureReceiver<R>,
) -> Result<Option<pb::session_message::Kind>> {
    loop {
        let Some(bytes) = rx.recv().await? else {
            return Ok(None);
        };
        // Les messages d'un milestone ultérieur (oneof inconnu) arrivent
        // sans `kind` : on les ignore pour rester compatible.
        if let Some(kind) = pb::SessionMessage::decode(bytes.as_slice())?.kind {
            return Ok(Some(kind));
        }
    }
}

/// Découpe une image encodée en messages `VideoChunk`.
pub(crate) fn chunks(
    display_id: u32,
    frame_id: u64,
    keyframe: bool,
    timestamp_us: u64,
    data: &[u8],
) -> impl Iterator<Item = pb::VideoChunk> + '_ {
    let count = data.len().div_ceil(CHUNK_SIZE).max(1) as u32;
    (0..count).map(move |i| {
        let start = i as usize * CHUNK_SIZE;
        let end = (start + CHUNK_SIZE).min(data.len());
        pb::VideoChunk {
            display_id,
            frame_id,
            keyframe,
            timestamp_us,
            chunk_index: i,
            chunk_count: count,
            data: data[start..end].to_vec(),
        }
    })
}

/// Réassemble les morceaux d'une image (flux fiable et ordonné).
#[derive(Default)]
pub(crate) struct Reassembler {
    current: Option<(u64, u32, Vec<u8>)>,
}

/// Image complète reçue du host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoFrame {
    pub display_id: u32,
    pub frame_id: u64,
    pub keyframe: bool,
    pub timestamp_us: u64,
    /// H.264 Annex B.
    pub data: Vec<u8>,
}

/// Taille maximale d'une image encodée acceptée par le viewer.
const MAX_FRAME_BYTES: usize = 32 << 20;

impl Reassembler {
    pub(crate) fn push(&mut self, c: pb::VideoChunk) -> Result<Option<VideoFrame>> {
        if c.chunk_count == 0 || c.chunk_index >= c.chunk_count {
            return Err(SessionError::Protocol("morceau d'image invalide"));
        }
        if c.chunk_index == 0 {
            self.current = Some((c.frame_id, 0, Vec::new()));
        }
        let Some((id, next, buf)) = &mut self.current else {
            return Err(SessionError::Protocol("morceau d'image orphelin"));
        };
        if *id != c.frame_id || *next != c.chunk_index {
            return Err(SessionError::Protocol("morceaux d'image désordonnés"));
        }
        if buf.len() + c.data.len() > MAX_FRAME_BYTES {
            return Err(SessionError::Protocol("image trop grande"));
        }
        buf.extend_from_slice(&c.data);
        *next += 1;
        if *next < c.chunk_count {
            return Ok(None);
        }
        let (_, _, data) = self.current.take().unwrap_or_default();
        Ok(Some(VideoFrame {
            display_id: c.display_id,
            frame_id: c.frame_id,
            keyframe: c.keyframe,
            timestamp_us: c.timestamp_us,
            data,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permissions_roundtrip() {
        let p = Permissions::VIEW | Permissions::CONTROL;
        assert_eq!(from_proto(Some(&to_proto(p))), p);
        assert_eq!(from_proto(None), Permissions::NONE);
        assert_eq!(
            intersect(p, Permissions::VIEW | Permissions::CLIPBOARD),
            Permissions::VIEW
        );
    }

    #[test]
    fn chunking_and_reassembly() {
        let data: Vec<u8> = (0..CHUNK_SIZE * 2 + 10).map(|i| i as u8).collect();
        let parts: Vec<_> = chunks(1, 7, true, 99, &data).collect();
        assert_eq!(parts.len(), 3);
        let mut r = Reassembler::default();
        assert!(r.push(parts[0].clone()).unwrap().is_none());
        assert!(r.push(parts[1].clone()).unwrap().is_none());
        let f = r.push(parts[2].clone()).unwrap().unwrap();
        assert_eq!((f.frame_id, f.keyframe, f.data), (7, true, data));
        // Morceau manquant : erreur de protocole.
        let mut r = Reassembler::default();
        r.push(parts[0].clone()).unwrap();
        assert!(r.push(parts[2].clone()).is_err());
        // Image vide : un seul morceau.
        assert_eq!(chunks(0, 1, false, 0, &[]).count(), 1);
    }
}
