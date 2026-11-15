//! Framing « longueur + charge utile » pour les flux fiables.
//!
//! Chaque trame est précédée de sa longueur sur 4 octets big-endian. La taille
//! maximale est bornée pour qu'un pair malveillant ne puisse pas forcer une
//! allocation arbitraire.

use bytes::{Buf, BufMut, BytesMut};
use prost::Message;

/// Taille maximale d'une trame (16 Mio).
pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

const HEADER_LEN: usize = 4;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("trame de {0} octets, au-delà du maximum de {MAX_FRAME_LEN}")]
    TooLarge(usize),
    #[error("message protobuf invalide : {0}")]
    Decode(#[from] prost::DecodeError),
}

/// Encode `msg` dans `dst`, préfixé de sa longueur.
pub fn encode<M: Message>(msg: &M, dst: &mut BytesMut) -> Result<(), FrameError> {
    let len = msg.encoded_len();
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(len));
    }
    dst.reserve(HEADER_LEN + len);
    // `len <= MAX_FRAME_LEN` tient dans un u32.
    dst.put_u32(len as u32);
    msg.encode(dst)
        .expect("la capacité a été réservée juste avant");
    Ok(())
}

/// Tente de décoder une trame complète depuis `src`.
///
/// Retourne `Ok(None)` s'il manque des octets ; dans ce cas `src` n'est pas
/// modifié et l'appelant doit lire davantage.
pub fn decode<M: Message + Default>(src: &mut BytesMut) -> Result<Option<M>, FrameError> {
    if src.len() < HEADER_LEN {
        return Ok(None);
    }
    let len = u32::from_be_bytes([src[0], src[1], src[2], src[3]]) as usize;
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(len));
    }
    if src.len() < HEADER_LEN + len {
        src.reserve(HEADER_LEN + len - src.len());
        return Ok(None);
    }
    src.advance(HEADER_LEN);
    let payload = src.split_to(len);
    Ok(Some(M::decode(payload.freeze())?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::v1::{PointerEvent, SessionMessage, session_message::Kind};

    fn pointer(x: f32) -> SessionMessage {
        SessionMessage {
            kind: Some(Kind::Pointer(PointerEvent {
                display_id: 1,
                x,
                y: 0.5,
                buttons: 1,
                wheel_dx: 0.0,
                wheel_dy: 0.0,
            })),
        }
    }

    #[test]
    fn roundtrip_several_frames() {
        let mut buf = BytesMut::new();
        encode(&pointer(0.1), &mut buf).unwrap();
        encode(&pointer(0.2), &mut buf).unwrap();

        let a: SessionMessage = decode(&mut buf).unwrap().unwrap();
        let b: SessionMessage = decode(&mut buf).unwrap().unwrap();
        assert_eq!(a, pointer(0.1));
        assert_eq!(b, pointer(0.2));
        assert!(buf.is_empty());
        assert!(decode::<SessionMessage>(&mut buf).unwrap().is_none());
    }

    #[test]
    fn partial_frame_waits_for_more_bytes() {
        let mut full = BytesMut::new();
        encode(&pointer(0.3), &mut full).unwrap();

        let mut partial = BytesMut::from(&full[..full.len() - 1]);
        assert!(decode::<SessionMessage>(&mut partial).unwrap().is_none());
        assert_eq!(partial.len(), full.len() - 1, "rien ne doit être consommé");

        partial.extend_from_slice(&full[full.len() - 1..]);
        let msg: SessionMessage = decode(&mut partial).unwrap().unwrap();
        assert_eq!(msg, pointer(0.3));
    }

    #[test]
    fn oversized_header_is_rejected() {
        let mut buf = BytesMut::new();
        buf.put_u32((MAX_FRAME_LEN + 1) as u32);
        assert!(matches!(
            decode::<SessionMessage>(&mut buf),
            Err(FrameError::TooLarge(_))
        ));
    }
}
