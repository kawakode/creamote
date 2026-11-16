//! Connexion au relay avec un jeton délivré par le rendezvous.

use std::pin::Pin;
use std::task::{Context, Poll};

use creamote_proto::rendezvous::v1::{
    RelayGrant, RelayJoin, RendezvousMessage, rendezvous_message::Kind,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::tls::ServerPin;
use crate::{Result, frame};

/// Flux bidirectionnel vers l'autre pair, à travers le relay. Il ne transporte
/// que des octets opaques : on y monte un [`crate::secure::SecureChannel`].
pub struct RelayStream {
    _endpoint: quinn::Endpoint,
    _conn: quinn::Connection,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl RelayStream {
    pub async fn join(
        relay_addr: std::net::SocketAddr,
        pin: ServerPin,
        grant: &RelayGrant,
    ) -> Result<Self> {
        let (endpoint, conn) = crate::tls::connect(relay_addr, pin).await?;
        let (mut send, recv) = conn.open_bi().await?;
        frame::write_msg(
            &mut send,
            &RendezvousMessage {
                kind: Some(Kind::RelayJoin(RelayJoin {
                    session_id: grant.session_id.clone(),
                    relay_token: grant.relay_token.clone(),
                })),
            },
        )
        .await?;
        Ok(Self {
            _endpoint: endpoint,
            _conn: conn,
            send,
            recv,
        })
    }
}

impl AsyncRead for RelayStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for RelayStream {
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
