//! Client du serveur de rendezvous.
//!
//! Un pair ouvre une connexion QUIC vers le serveur, puis un flux de contrôle
//! sur lequel il s'enregistre en prouvant la possession de sa clé d'identité.
//! Le même flux sert ensuite dans les deux sens : demandes de session (côté
//! viewer), offres entrantes (côté host), jetons relay.

use std::net::SocketAddr;

use creamote_crypto::{DeviceId, DeviceIdentity};
use creamote_proto::common::v1::Platform;
use creamote_proto::rendezvous::v1::{
    ConnectAnswer, ConnectRequest, RegisterPeer, RendezvousMessage, rendezvous_message::Kind,
};
pub use creamote_proto::rendezvous::v1::{
    ConnectOffer, ConnectRejected, RegisterPeerResponse, RelayGrant,
};
use rand_core::{OsRng, RngCore};

use crate::tls::ServerPin;
use crate::{NetError, RegisterStatus, RejectReason, Result, frame, ident};

/// Événement reçu du serveur.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// Un viewer demande à se connecter à cet appareil.
    Offer(ConnectOffer),
    /// Jeton pour rejoindre le relay d'une session acceptée.
    Grant(RelayGrant),
    /// Une demande a été refusée.
    Rejected(ConnectRejected),
}

pub struct RendezvousClient {
    _endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    server_addr: SocketAddr,
    pin: ServerPin,
    registration: RegisterPeerResponse,
}

impl RendezvousClient {
    /// Se connecte au serveur d'empreinte `pin` et y enregistre `identity`.
    pub async fn register(
        server_addr: SocketAddr,
        pin: ServerPin,
        identity: &DeviceIdentity,
    ) -> Result<Self> {
        let (endpoint, conn) = crate::tls::connect(server_addr, pin).await?;
        let (mut send, mut recv) = conn.open_bi().await?;

        let register = RegisterPeer {
            identity: Some(ident::to_proto(identity.public())),
            platform: current_platform() as i32,
            version: Some(creamote_proto::PROTOCOL_VERSION),
            local_addrs: Vec::new(),
            proof: ident::register_proof(&conn, identity)?,
        };
        frame::write_msg(
            &mut send,
            &RendezvousMessage {
                kind: Some(Kind::RegisterPeer(register)),
            },
        )
        .await?;

        let reply: RendezvousMessage = frame::read_msg(&mut recv).await?.ok_or(NetError::Closed)?;
        let registration = match reply.kind {
            Some(Kind::RegisterPeerResponse(r)) => r,
            _ => return Err(NetError::Protocol("réponse d'enregistrement attendue")),
        };
        let status = registration.status();
        if status != RegisterStatus::Ok {
            return Err(NetError::Registration(status));
        }
        Ok(Self {
            _endpoint: endpoint,
            conn,
            send,
            recv,
            server_addr,
            pin,
            registration,
        })
    }

    pub fn registration(&self) -> &RegisterPeerResponse {
        &self.registration
    }

    pub fn pin(&self) -> ServerPin {
        self.pin
    }

    /// Adresse du relay d'un jeton (celle du serveur si non précisée).
    pub fn relay_addr(&self, grant: &RelayGrant) -> Result<SocketAddr> {
        if grant.relay_addr.is_empty() {
            return Ok(self.server_addr);
        }
        grant
            .relay_addr
            .parse()
            .map_err(|_| NetError::Protocol("adresse de relay invalide"))
    }

    /// Attend le prochain événement ; `Ok(None)` si le serveur a fermé.
    pub async fn next_event(&mut self) -> Result<Option<Event>> {
        loop {
            let Some(msg): Option<RendezvousMessage> = frame::read_msg(&mut self.recv).await?
            else {
                return Ok(None);
            };
            match msg.kind {
                Some(Kind::ConnectOffer(o)) => return Ok(Some(Event::Offer(o))),
                Some(Kind::RelayGrant(g)) => return Ok(Some(Event::Grant(g))),
                Some(Kind::ConnectRejected(r)) => return Ok(Some(Event::Rejected(r))),
                other => tracing::debug!(?other, "message de rendezvous ignoré"),
            }
        }
    }

    /// Demande une session vers `target` et attend le jeton relay.
    pub async fn request_session(&mut self, target: DeviceId) -> Result<RelayGrant> {
        let request_id = OsRng.next_u64().max(1);
        let req = ConnectRequest {
            target_device_id: target.to_string(),
            requester: None,
            session_ticket: Vec::new(),
            request_id,
        };
        frame::write_msg(
            &mut self.send,
            &RendezvousMessage {
                kind: Some(Kind::ConnectRequest(req)),
            },
        )
        .await?;
        loop {
            match self.next_event().await?.ok_or(NetError::Closed)? {
                Event::Grant(g) if g.request_id == request_id => return Ok(g),
                Event::Rejected(r) if r.request_id == request_id => {
                    return Err(NetError::Rejected(r.reason()));
                }
                other => tracing::debug!(?other, "événement sans rapport ignoré"),
            }
        }
    }

    /// Répond à une offre entrante. Si elle est acceptée, le jeton relay
    /// arrive ensuite comme [`Event::Grant`] portant le même `session_id`.
    pub async fn answer(&mut self, offer: &ConnectOffer, accepted: bool) -> Result<()> {
        let answer = ConnectAnswer {
            session_id: offer.session_id.clone(),
            accepted,
            host_observed_addr: String::new(),
            host_local_addrs: Vec::new(),
        };
        frame::write_msg(
            &mut self.send,
            &RendezvousMessage {
                kind: Some(Kind::ConnectAnswer(answer)),
            },
        )
        .await
    }

    pub fn close(&self) {
        self.conn.close(0u32.into(), b"bye");
    }
}

impl From<RejectReason> for NetError {
    fn from(r: RejectReason) -> Self {
        NetError::Rejected(r)
    }
}

fn current_platform() -> Platform {
    if cfg!(target_os = "android") {
        Platform::Android
    } else if cfg!(target_os = "windows") {
        Platform::Windows
    } else if cfg!(target_os = "macos") {
        Platform::Macos
    } else if cfg!(target_os = "linux") {
        Platform::Linux
    } else {
        Platform::Unspecified
    }
}
