//! Trames sur un flux asynchrone : messages protobuf, ou octets bruts (pour
//! les messages Noise). Préfixe de longueur u32 big-endian.

use bytes::BytesMut;
use prost::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{NetError, Result};

/// Taille maximale d'un message de contrôle (rendezvous).
pub const MAX_CONTROL_LEN: usize = 64 * 1024;

pub async fn write_msg<W, M>(w: &mut W, msg: &M) -> Result<()>
where
    W: AsyncWrite + Unpin,
    M: Message,
{
    let mut buf = BytesMut::new();
    creamote_proto::framing::encode(msg, &mut buf)?;
    w.write_all(&buf).await?;
    Ok(())
}

/// Lit un message ; `Ok(None)` si le flux s'est fermé proprement.
pub async fn read_msg<R, M>(r: &mut R) -> Result<Option<M>>
where
    R: AsyncRead + Unpin,
    M: Message + Default,
{
    match read_raw(r, MAX_CONTROL_LEN).await? {
        Some(bytes) => Ok(Some(M::decode(bytes.as_slice()).map_err(|e| {
            NetError::Frame(creamote_proto::framing::FrameError::Decode(e))
        })?)),
        None => Ok(None),
    }
}

pub async fn write_raw<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> Result<()> {
    let len = u32::try_from(data.len()).map_err(|_| NetError::Protocol("trame trop grande"))?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(data).await?;
    Ok(())
}

/// Lit une trame brute d'au plus `max` octets ; `Ok(None)` en fin de flux.
pub async fn read_raw<R: AsyncRead + Unpin>(r: &mut R, max: usize) -> Result<Option<Vec<u8>>> {
    let mut header = [0u8; 4];
    match r.read_exact(&mut header).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(header) as usize;
    if len > max {
        return Err(NetError::Protocol("trame au-delà de la taille autorisée"));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use creamote_proto::rendezvous::v1::RelayJoin;

    #[tokio::test]
    async fn msg_roundtrip_and_eof() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let msg = RelayJoin {
            session_id: vec![1; 16],
            relay_token: vec![2; 32],
        };
        write_msg(&mut a, &msg).await.unwrap();
        drop(a);
        let got: RelayJoin = read_msg(&mut b).await.unwrap().unwrap();
        assert_eq!(got, msg);
        assert!(read_msg::<_, RelayJoin>(&mut b).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn oversized_raw_frame_is_rejected() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        write_raw(&mut a, &[0u8; 100]).await.unwrap();
        assert!(read_raw(&mut b, 99).await.is_err());
    }
}
