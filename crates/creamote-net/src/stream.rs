//! Flux bidirectionnel vers l'autre pair, direct ou à travers le relay.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Chemin emprunté par un [`PeerStream`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerPath {
    /// Connexion QUIC directe entre les pairs (LAN ou hole punching).
    Direct,
    /// À travers le relay du serveur.
    Relay,
}

/// Flux bidirectionnel vers l'autre pair. Il ne transporte que des octets
/// opaques : on y monte un [`crate::secure::SecureChannel`].
pub struct PeerStream {
    _endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    path: PeerPath,
    /// Octets déjà lus (pour détecter le choix du viewer), rendus en premier.
    prefix: Vec<u8>,
}

impl PeerStream {
    pub(crate) fn new(
        endpoint: quinn::Endpoint,
        conn: quinn::Connection,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        path: PeerPath,
    ) -> Self {
        Self {
            _endpoint: endpoint,
            conn,
            send,
            recv,
            path,
            prefix: Vec::new(),
        }
    }

    pub fn path(&self) -> PeerPath {
        self.path
    }

    /// Adresse de l'autre extrémité de la connexion QUIC (le pair en direct,
    /// le relay sinon).
    pub fn remote_address(&self) -> std::net::SocketAddr {
        self.conn.remote_address()
    }

    /// Connexion QUIC directe vers le pair, pour y ouvrir d'autres flux ou
    /// envoyer des datagrammes (vidéo). `None` à travers le relay.
    pub fn direct_connection(&self) -> Option<&quinn::Connection> {
        (self.path == PeerPath::Direct).then_some(&self.conn)
    }

    /// Attend le premier octet envoyé par le pair et le conserve pour la
    /// prochaine lecture. `Ok(false)` si le flux s'est fermé avant.
    pub(crate) async fn wait_readable(&mut self) -> std::io::Result<bool> {
        if !self.prefix.is_empty() {
            return Ok(true);
        }
        let mut b = [0u8; 1];
        match self.recv.read(&mut b).await {
            Ok(Some(n)) if n > 0 => {
                self.prefix.push(b[0]);
                Ok(true)
            }
            Ok(_) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
}

impl AsyncRead for PeerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.prefix.is_empty() {
            let n = self.prefix.len().min(buf.remaining());
            buf.put_slice(&self.prefix[..n]);
            self.prefix.drain(..n);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for PeerStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}
