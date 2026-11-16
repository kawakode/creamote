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
    ConnectAnswer, ConnectRequest, EnrollRequest, RegisterPeer, RendezvousMessage,
    rendezvous_message::Kind,
};
pub use creamote_proto::rendezvous::v1::{
    ConnectOffer, ConnectRejected, EnrollResponse, RegisterPeerResponse, RelayGrant,
};
use rand_core::{OsRng, RngCore};

pub use crate::p2p::Connector;
use crate::tls::ServerPin;
use crate::{EnrollStatus, NetError, RegisterStatus, RejectReason, Result, frame, ident};

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

/// Options d'enregistrement.
#[derive(Debug, Clone, Copy, Default)]
pub struct RegisterOptions {
    /// Accepter les connexions directes entrantes (rôle host).
    pub accept_direct: bool,
    /// Refuser la connexion directe : les adresses de cet appareil ne sont
    /// jamais communiquées à l'autre pair, toutes les sessions passent par
    /// le relay.
    pub relay_only: bool,
}

pub struct RendezvousClient {
    endpoint: quinn::Endpoint,
    acceptor: Option<crate::p2p::DirectAcceptor>,
    _accept_task: Option<AbortOnDrop>,
    conn: quinn::Connection,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    server_addr: SocketAddr,
    pin: ServerPin,
    registration: RegisterPeerResponse,
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl RendezvousClient {
    /// Se connecte au serveur d'empreinte `pin` et y enregistre `identity`
    /// (rôle viewer : connexions directes sortantes uniquement).
    pub async fn register(
        server_addr: SocketAddr,
        pin: ServerPin,
        identity: &DeviceIdentity,
    ) -> Result<Self> {
        Self::register_with(server_addr, pin, identity, RegisterOptions::default()).await
    }

    /// Comme [`Self::register`], avec des options (host : `accept_direct`).
    pub async fn register_with(
        server_addr: SocketAddr,
        pin: ServerPin,
        identity: &DeviceIdentity,
        options: RegisterOptions,
    ) -> Result<Self> {
        // Un seul endpoint pour le rendezvous, le direct et le relay : la
        // correspondance NAT observée par le serveur est celle qui servira
        // au hole punching.
        let server_cfg = if options.accept_direct && !options.relay_only {
            Some(crate::tls::p2p_server_config()?)
        } else {
            None
        };
        let endpoint = crate::tls::endpoint_for(server_addr, server_cfg)?;
        let conn = crate::tls::connect_on(&endpoint, server_addr, pin).await?;
        let (mut send, mut recv) = conn.open_bi().await?;

        let local_addrs = if options.relay_only {
            Vec::new()
        } else {
            let local = endpoint.local_addr()?;
            crate::p2p::local_addrs(local, local.port())
        };
        let register = RegisterPeer {
            identity: Some(ident::to_proto(identity.public())),
            platform: current_platform() as i32,
            version: Some(creamote_proto::PROTOCOL_VERSION),
            local_addrs,
            proof: ident::register_proof(&conn, identity)?,
            relay_only: options.relay_only,
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
        let (acceptor, accept_task) = if options.accept_direct && !options.relay_only {
            let acceptor = crate::p2p::DirectAcceptor::default();
            let task = acceptor.spawn(endpoint.clone());
            (Some(acceptor), Some(AbortOnDrop(task)))
        } else {
            (None, None)
        };
        Ok(Self {
            endpoint,
            acceptor,
            _accept_task: accept_task,
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
        crate::p2p::relay_addr(self.server_addr, grant)
    }

    /// Établit le flux d'une session acceptée (direct ou relay), depuis
    /// n'importe quelle tâche : [`Connector::viewer`] ou [`Connector::host`].
    pub fn connector(&self) -> Connector {
        Connector {
            endpoint: self.endpoint.clone(),
            server_addr: self.server_addr,
            pin: self.pin,
            acceptor: self.acceptor.clone(),
        }
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

    /// Enrôle cet appareil dans le parc désigné par un jeton d'enrôlement.
    pub async fn enroll(&mut self, token: &str, name: &str) -> Result<EnrollResponse> {
        frame::write_msg(
            &mut self.send,
            &RendezvousMessage {
                kind: Some(Kind::EnrollRequest(EnrollRequest {
                    token: token.to_owned(),
                    name: name.to_owned(),
                })),
            },
        )
        .await?;
        loop {
            let msg: RendezvousMessage = frame::read_msg(&mut self.recv)
                .await?
                .ok_or(NetError::Closed)?;
            if let Some(Kind::EnrollResponse(r)) = msg.kind {
                return match r.status() {
                    EnrollStatus::Ok => Ok(r),
                    other => Err(NetError::Enrollment(other)),
                };
            }
        }
    }

    /// Demande une session vers `target` et attend le jeton relay.
    pub async fn request_session(&mut self, target: DeviceId) -> Result<RelayGrant> {
        self.request_session_with_ticket(target, Vec::new()).await
    }

    /// Comme [`Self::request_session`], avec un ticket signé par le serveur de
    /// gestion (exigé par un host enrôlé).
    pub async fn request_session_with_ticket(
        &mut self,
        target: DeviceId,
        session_ticket: Vec<u8>,
    ) -> Result<RelayGrant> {
        let request_id = OsRng.next_u64().max(1);
        let req = ConnectRequest {
            target_device_id: target.to_string(),
            requester: None,
            session_ticket,
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
        if let (true, Some(acceptor)) = (accepted, &self.acceptor) {
            acceptor.arm();
        }
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
