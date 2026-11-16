//! Connexion au relay avec un jeton délivré par le rendezvous.

use std::net::SocketAddr;

use creamote_proto::rendezvous::v1::{
    RelayGrant, RelayJoin, RendezvousMessage, rendezvous_message::Kind,
};

use crate::stream::{PeerPath, PeerStream};
use crate::tls::ServerPin;
use crate::{Result, frame};

/// Flux à travers le relay (nom historique de [`PeerStream`]).
pub type RelayStream = PeerStream;

impl PeerStream {
    /// Rejoint le relay depuis un nouvel endpoint.
    pub async fn join(relay_addr: SocketAddr, pin: ServerPin, grant: &RelayGrant) -> Result<Self> {
        let endpoint = crate::tls::endpoint_for(relay_addr, None)?;
        join_on(endpoint, relay_addr, pin, grant).await
    }
}

/// Rejoint le relay depuis `endpoint` (celui du rendezvous, typiquement).
pub async fn join_on(
    endpoint: quinn::Endpoint,
    relay_addr: SocketAddr,
    pin: ServerPin,
    grant: &RelayGrant,
) -> Result<PeerStream> {
    let conn = crate::tls::connect_on(&endpoint, relay_addr, pin).await?;
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
    Ok(PeerStream::new(endpoint, conn, send, recv, PeerPath::Relay))
}
