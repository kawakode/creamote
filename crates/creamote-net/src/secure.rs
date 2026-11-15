//! Canal chiffré de bout en bout au-dessus d'un flux quelconque.

use creamote_crypto::noise::MAX_NOISE_MSG_LEN;
use creamote_crypto::{DeviceIdentity, Initiator, PublicIdentity, Responder, SecureSession};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::{NetError, Result, frame};

pub use creamote_crypto::noise::MAX_PLAINTEXT_LEN;

pub struct SecureChannel<T> {
    io: T,
    session: SecureSession,
    remote: PublicIdentity,
}

impl<T: AsyncRead + AsyncWrite + Unpin> SecureChannel<T> {
    /// Handshake côté initiateur (viewer).
    pub async fn initiate(mut io: T, local: &DeviceIdentity) -> Result<Self> {
        let (init, msg1) = Initiator::start(local)?;
        frame::write_raw(&mut io, &msg1).await?;
        let msg2 = read_noise(&mut io).await?;
        let (session, msg3, remote) = init.finish(&msg2)?;
        frame::write_raw(&mut io, &msg3).await?;
        io.flush().await?;
        Ok(Self {
            io,
            session,
            remote,
        })
    }

    /// Handshake côté répondeur (host).
    pub async fn respond(mut io: T, local: &DeviceIdentity) -> Result<Self> {
        let msg1 = read_noise(&mut io).await?;
        let (waiting, msg2) = Responder::new(local)?.respond(&msg1)?;
        frame::write_raw(&mut io, &msg2).await?;
        io.flush().await?;
        let msg3 = read_noise(&mut io).await?;
        let (session, remote) = waiting.finish(&msg3)?;
        Ok(Self {
            io,
            session,
            remote,
        })
    }

    /// Identité vérifiée du pair.
    pub fn remote(&self) -> &PublicIdentity {
        &self.remote
    }

    /// Code à 6 chiffres identique des deux côtés, à comparer de vive voix
    /// pour exclure une interception.
    pub fn verification_code(&self) -> String {
        let h = self.session.handshake_hash();
        let n = u32::from_le_bytes([h[0], h[1], h[2], h[3]]) % 1_000_000;
        format!("{n:06}")
    }

    pub async fn send(&mut self, plaintext: &[u8]) -> Result<()> {
        let c = self.session.encrypt(plaintext)?;
        frame::write_raw(&mut self.io, &c).await?;
        self.io.flush().await?;
        Ok(())
    }

    /// Prochain message ; `Ok(None)` si le pair a fermé le canal.
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>> {
        match frame::read_raw(&mut self.io, MAX_NOISE_MSG_LEN).await? {
            Some(c) => Ok(Some(self.session.decrypt(&c)?)),
            None => Ok(None),
        }
    }

    pub async fn close(mut self) -> Result<()> {
        self.io.shutdown().await?;
        Ok(())
    }
}

async fn read_noise<T: AsyncRead + Unpin>(io: &mut T) -> Result<Vec<u8>> {
    frame::read_raw(io, MAX_NOISE_MSG_LEN)
        .await?
        .ok_or(NetError::Closed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn channel_over_duplex() {
        let (a, b) = tokio::io::duplex(4096);
        let viewer = DeviceIdentity::generate();
        let host = DeviceIdentity::generate();
        let (v, h) = tokio::join!(
            SecureChannel::initiate(a, &viewer),
            SecureChannel::respond(b, &host)
        );
        let (mut v, mut h) = (v.unwrap(), h.unwrap());
        assert_eq!(v.remote(), host.public());
        assert_eq!(h.remote(), viewer.public());
        assert_eq!(v.verification_code(), h.verification_code());

        v.send(b"bonjour").await.unwrap();
        assert_eq!(h.recv().await.unwrap().unwrap(), b"bonjour");
        h.send(b"salut").await.unwrap();
        assert_eq!(v.recv().await.unwrap().unwrap(), b"salut");

        v.close().await.unwrap();
        assert!(h.recv().await.unwrap().is_none());
    }
}
