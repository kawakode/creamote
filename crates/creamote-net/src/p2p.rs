//! Connexion directe entre pairs : LAN, puis hole punching UDP, avec repli
//! sur le relay.
//!
//! Chaque pair s'enregistre auprès du rendezvous depuis un endpoint QUIC
//! unique : l'adresse publique observée par le serveur est donc celle de la
//! correspondance NAT que ce même endpoint utilisera vers l'autre pair. Le
//! serveur transmet à chacun les adresses candidates de l'autre (observée,
//! puis adresses LAN) dans le [`RelayGrant`].
//!
//! Les rôles sont fixes : le **viewer** est client QUIC, le **host** est
//! serveur. Le host envoie lui aussi des paquets vers les adresses du viewer
//! (tentatives de connexion qui échouent) : ils ouvrent sa propre
//! correspondance NAT pour que les paquets du viewer passent.
//!
//! Le viewer décide du chemin. Il rejoint le relay en parallèle (si un jeton
//! est disponible) et laisse [`DIRECT_WINDOW`] au direct. S'il obtient une
//! connexion directe, il y envoie un [`DirectJoin`] et abandonne le relay ;
//! sinon il parle sur le relay. Le host utilise le premier des deux chemins
//! sur lequel le viewer s'exprime.
//!
//! TLS n'est pas vérifié sur une connexion directe (le certificat du host est
//! éphémère) : les pairs s'authentifient ensuite par Noise, exactement comme
//! à travers le relay.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use creamote_proto::rendezvous::v1::{
    DirectJoin, RelayGrant, RendezvousMessage, rendezvous_message::Kind,
};
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::stream::{PeerPath, PeerStream};
use crate::tls::ServerPin;
use crate::{NetError, RejectReason, Result, frame};

/// Temps laissé à la connexion directe avant de passer par le relay.
pub const DIRECT_WINDOW: Duration = Duration::from_secs(3);
/// Temps laissé à la connexion directe quand le relay est indisponible.
pub const DIRECT_ONLY_TIMEOUT: Duration = Duration::from_secs(8);
/// Délai maximal d'établissement côté host (le relay attend 30 s).
const HOST_TIMEOUT: Duration = Duration::from_secs(30);
/// Instants des tentatives vers chaque candidat : chaque tentative ouvre une
/// nouvelle connexion, pour ne pas dépendre du rythme de retransmission de
/// QUIC pendant que les NAT s'ouvrent.
const ATTEMPTS_MS: [u64; 5] = [0, 250, 750, 1500, 2500];
/// Nombre maximal d'adresses candidates retenues.
pub const MAX_CANDIDATES: usize = 8;
/// Nom TLS des connexions directes (non vérifié).
const PEER_SERVER_NAME: &str = "creamote-peer";
/// Connexions directes arrivées avant que le host n'attende leur session.
const MAX_EARLY: usize = 64;
const EARLY_TTL: Duration = Duration::from_secs(10);

/// Adresses LAN de cette machine pour un endpoint écoutant sur `port`, dans
/// la famille de `like`. Énumérées par l'OS (`getifaddrs`,
/// `GetAdaptersAddresses`). Les adresses de bouclage et lien-local sont
/// exclues.
pub fn local_addrs(like: SocketAddr, port: u16) -> Vec<String> {
    let Ok(ifaces) = if_addrs::get_if_addrs() else {
        return Vec::new();
    };
    let mut out: Vec<String> = ifaces
        .into_iter()
        .filter(|i| !i.is_loopback())
        .map(|i| i.ip())
        .filter(|ip| ip.is_ipv6() == like.is_ipv6() && usable(ip))
        .map(|ip| SocketAddr::new(ip, port).to_string())
        .collect();
    out.dedup();
    out.truncate(MAX_CANDIDATES);
    out
}

fn usable(ip: &IpAddr) -> bool {
    if ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => !v4.is_link_local() && !v4.is_broadcast(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) != 0xfe80,
    }
}

/// Candidats exploitables depuis un endpoint de la famille de `local`.
pub fn parse_candidates(list: &[String], local: SocketAddr) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::new();
    for a in list {
        let Ok(addr) = a.parse::<SocketAddr>() else {
            continue;
        };
        if addr.port() == 0 || addr.is_ipv6() != local.is_ipv6() || !usable_remote(&addr.ip()) {
            continue;
        }
        if !out.contains(&addr) {
            out.push(addr);
        }
        if out.len() == MAX_CANDIDATES {
            break;
        }
    }
    out
}

fn usable_remote(ip: &IpAddr) -> bool {
    !ip.is_unspecified() && !ip.is_multicast()
}

/// Connexions directes entrantes (host), réparties par session. Elles ne
/// sont acceptées que peu après une offre acceptée : le reste du temps, le
/// host refuse toute connexion entrante.
#[derive(Clone, Default)]
pub(crate) struct DirectAcceptor {
    slots: Arc<Mutex<HashMap<Vec<u8>, Slot>>>,
    armed_until: Arc<Mutex<Option<Instant>>>,
}

enum Slot {
    Waiting(oneshot::Sender<PeerStream>),
    Early(PeerStream, Instant),
}

impl DirectAcceptor {
    /// Accepte les connexions entrantes de `endpoint` jusqu'à sa fermeture.
    pub(crate) fn spawn(&self, endpoint: quinn::Endpoint) -> tokio::task::JoinHandle<()> {
        let this = self.clone();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                if !this.armed() {
                    incoming.refuse();
                    continue;
                }
                let this = this.clone();
                let endpoint = endpoint.clone();
                tokio::spawn(async move {
                    match tokio::time::timeout(EARLY_TTL, accept_one(endpoint, incoming)).await {
                        Ok(Ok((session_id, stream))) => this.deliver(session_id, stream),
                        Ok(Err(e)) => tracing::debug!("connexion directe refusée : {e}"),
                        Err(_) => tracing::debug!("connexion directe sans session"),
                    }
                });
            }
        })
    }

    /// Ouvre la fenêtre d'acceptation (offre acceptée).
    pub(crate) fn arm(&self) {
        *self.armed_until.lock().expect("verrou sain") = Some(Instant::now() + HOST_TIMEOUT);
    }

    fn armed(&self) -> bool {
        let slots_waiting = self
            .slots
            .lock()
            .expect("verrou sain")
            .values()
            .any(|s| matches!(s, Slot::Waiting(_)));
        slots_waiting
            || self
                .armed_until
                .lock()
                .expect("verrou sain")
                .is_some_and(|t| Instant::now() < t)
    }

    fn deliver(&self, session_id: Vec<u8>, stream: PeerStream) {
        let mut slots = self.slots.lock().expect("verrou sain");
        slots.retain(|_, s| !matches!(s, Slot::Early(_, t) if t.elapsed() > EARLY_TTL));
        match slots.remove(&session_id) {
            Some(Slot::Waiting(tx)) => {
                let _ = tx.send(stream);
            }
            // Une connexion pour cette session est déjà là : on garde la
            // première.
            Some(early @ Slot::Early(..)) => {
                slots.insert(session_id, early);
            }
            None if slots.len() < MAX_EARLY => {
                slots.insert(session_id, Slot::Early(stream, Instant::now()));
            }
            None => {}
        }
    }

    fn expect(&self, session_id: &[u8]) -> oneshot::Receiver<PeerStream> {
        let (tx, rx) = oneshot::channel();
        let mut slots = self.slots.lock().expect("verrou sain");
        match slots.remove(session_id) {
            Some(Slot::Early(stream, _)) => {
                let _ = tx.send(stream);
            }
            _ => {
                slots.insert(session_id.to_vec(), Slot::Waiting(tx));
            }
        }
        rx
    }

    fn cancel(&self, session_id: &[u8]) {
        self.slots.lock().expect("verrou sain").remove(session_id);
    }
}

async fn accept_one(
    endpoint: quinn::Endpoint,
    incoming: quinn::Incoming,
) -> Result<(Vec<u8>, PeerStream)> {
    let conn = incoming.await?;
    let (send, mut recv) = conn.accept_bi().await?;
    let msg: RendezvousMessage = frame::read_msg(&mut recv).await?.ok_or(NetError::Closed)?;
    let Some(Kind::DirectJoin(DirectJoin { session_id })) = msg.kind else {
        return Err(NetError::Protocol("DirectJoin attendu"));
    };
    Ok((
        session_id,
        PeerStream::new(endpoint, conn, send, recv, PeerPath::Direct),
    ))
}

/// Établit le flux vers l'autre pair d'une session acceptée. Obtenu par
/// [`crate::rendezvous::RendezvousClient::connector`] ; clonable et
/// utilisable depuis d'autres tâches.
#[derive(Clone)]
pub struct Connector {
    pub(crate) endpoint: quinn::Endpoint,
    pub(crate) server_addr: SocketAddr,
    pub(crate) pin: ServerPin,
    pub(crate) acceptor: Option<DirectAcceptor>,
}

impl Connector {
    /// Adresse du relay d'un jeton (celle du serveur si non précisée).
    pub fn relay_addr(&self, grant: &RelayGrant) -> Result<SocketAddr> {
        relay_addr(self.server_addr, grant)
    }

    fn local(&self) -> Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }

    fn spawn_relay(
        &self,
        grant: &RelayGrant,
    ) -> Result<Option<tokio::task::JoinHandle<Result<PeerStream>>>> {
        if grant.relay_token.is_empty() {
            return Ok(None);
        }
        let relay = self.relay_addr(grant)?;
        let (endpoint, pin, grant) = (self.endpoint.clone(), self.pin, grant.clone());
        Ok(Some(tokio::spawn(async move {
            crate::relay::join_on(endpoint, relay, pin, &grant).await
        })))
    }

    fn unavailable(grant: &RelayGrant) -> NetError {
        match grant.relay_unavailable() {
            RejectReason::Unspecified => NetError::Protocol("connexion directe impossible"),
            reason => NetError::Rejected(reason),
        }
    }

    /// Côté viewer : connexion directe si possible, relay sinon.
    pub async fn viewer(&self, grant: &RelayGrant) -> Result<PeerStream> {
        let candidates = parse_candidates(&grant.peer_addrs, self.local()?);
        let relay = self.spawn_relay(grant)?;
        let window = if relay.is_some() {
            DIRECT_WINDOW
        } else {
            DIRECT_ONLY_TIMEOUT
        };
        if !candidates.is_empty() {
            if let Ok(Some(conn)) =
                tokio::time::timeout(window, dial(&self.endpoint, &candidates)).await
            {
                match commit(self.endpoint.clone(), conn, &grant.session_id).await {
                    Ok(stream) => {
                        if let Some(r) = relay {
                            r.abort();
                        }
                        tracing::info!(peer = %stream.remote_address(), "connexion directe établie");
                        return Ok(stream);
                    }
                    Err(e) => tracing::debug!("connexion directe perdue : {e}"),
                }
            }
        }
        match relay {
            Some(r) => {
                let stream = r
                    .await
                    .map_err(|_| NetError::Protocol("tâche relay interrompue"))??;
                tracing::info!("connexion directe impossible, passage par le relay");
                Ok(stream)
            }
            None => Err(Self::unavailable(grant)),
        }
    }

    /// Côté host : utilise le chemin choisi par le viewer.
    pub async fn host(&self, grant: &RelayGrant) -> Result<PeerStream> {
        let candidates = parse_candidates(&grant.peer_addrs, self.local()?);
        let direct = match (&self.acceptor, candidates.is_empty()) {
            (Some(a), false) => Some((a, a.expect(&grant.session_id))),
            _ => None,
        };
        let _punch = direct
            .is_some()
            .then(|| AbortOnDrop(tokio::spawn(punch(self.endpoint.clone(), candidates))));

        let relay = self.spawn_relay(grant)?.map(|task| async move {
            let mut stream = task
                .await
                .map_err(|_| NetError::Protocol("tâche relay interrompue"))??;
            // Le viewer ne parle sur le relay que s'il l'a choisi.
            if stream.wait_readable().await? {
                Ok(stream)
            } else {
                Err(NetError::Closed)
            }
        });
        if direct.is_none() && relay.is_none() {
            return Err(Self::unavailable(grant));
        }
        let timeout = if relay.is_some() {
            HOST_TIMEOUT
        } else {
            DIRECT_ONLY_TIMEOUT + Duration::from_secs(2)
        };
        let (acceptor, direct_rx) = match direct {
            Some((a, rx)) => (Some(a), Some(rx)),
            None => (None, None),
        };
        let result = tokio::time::timeout(timeout, async {
            let direct = async {
                match direct_rx {
                    Some(rx) => rx.await.map_err(|_| NetError::Closed),
                    None => std::future::pending().await,
                }
            };
            tokio::pin!(direct);
            match relay {
                Some(relay) => tokio::select! {
                    d = &mut direct => d,
                    r = relay => match r {
                        Ok(stream) => Ok(stream),
                        // Relay abandonné par le viewer : il est passé en direct.
                        Err(_) if acceptor.is_some() => direct.await,
                        Err(e) => Err(e),
                    },
                },
                None => direct.await,
            }
        })
        .await
        .unwrap_or(Err(NetError::Protocol("le viewer ne s'est pas présenté")));
        if let Some(a) = acceptor {
            a.cancel(&grant.session_id);
        }
        if let Ok(s) = &result {
            tracing::info!(path = ?s.path(), peer = %s.remote_address(), "session établie");
        }
        result
    }
}

pub(crate) fn relay_addr(server: SocketAddr, grant: &RelayGrant) -> Result<SocketAddr> {
    if grant.relay_addr.is_empty() {
        return Ok(server);
    }
    grant
        .relay_addr
        .parse()
        .map_err(|_| NetError::Protocol("adresse de relay invalide"))
}

struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Tente des connexions vers chaque candidat selon [`ATTEMPTS_MS`] ; renvoie
/// la première établie, `None` si toutes échouent.
async fn dial(endpoint: &quinn::Endpoint, candidates: &[SocketAddr]) -> Option<quinn::Connection> {
    let cfg = crate::tls::p2p_client_config().ok()?;
    let mut set = JoinSet::new();
    for delay in ATTEMPTS_MS {
        for &addr in candidates {
            let (endpoint, cfg) = (endpoint.clone(), cfg.clone());
            set.spawn(async move {
                tokio::time::sleep(Duration::from_millis(delay)).await;
                endpoint
                    .connect_with(cfg, addr, PEER_SERVER_NAME)
                    .map_err(NetError::from)?
                    .await
                    .map_err(NetError::from)
            });
        }
    }
    while let Some(r) = set.join_next().await {
        if let Ok(Ok(conn)) = r {
            return Some(conn);
        }
    }
    None
}

/// Le viewer s'engage sur la connexion directe.
async fn commit(
    endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    session_id: &[u8],
) -> Result<PeerStream> {
    let (mut send, recv) = conn.open_bi().await?;
    frame::write_msg(
        &mut send,
        &RendezvousMessage {
            kind: Some(Kind::DirectJoin(DirectJoin {
                session_id: session_id.to_vec(),
            })),
        },
    )
    .await?;
    Ok(PeerStream::new(
        endpoint,
        conn,
        send,
        recv,
        PeerPath::Direct,
    ))
}

/// Ouvre la correspondance NAT du host vers le viewer : tentatives de
/// connexion vers ses candidats, vouées à échouer (le viewer n'accepte pas de
/// connexion entrante), maintenues pendant la fenêtre du direct.
async fn punch(endpoint: quinn::Endpoint, candidates: Vec<SocketAddr>) {
    let Ok(cfg) = crate::tls::p2p_client_config() else {
        return;
    };
    let mut set = JoinSet::new();
    for delay in ATTEMPTS_MS {
        for &addr in &candidates {
            let (endpoint, cfg) = (endpoint.clone(), cfg.clone());
            set.spawn(async move {
                tokio::time::sleep(Duration::from_millis(delay)).await;
                if let Ok(connecting) = endpoint.connect_with(cfg, addr, PEER_SERVER_NAME) {
                    let _ = tokio::time::timeout(DIRECT_WINDOW, connecting).await;
                }
            });
        }
    }
    while set.join_next().await.is_some() {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidates_are_filtered_and_deduplicated() {
        let local: SocketAddr = "0.0.0.0:5000".parse().unwrap();
        let list = [
            "203.0.113.7:4000",
            "203.0.113.7:4000",
            "[2001:db8::1]:4000",
            "0.0.0.0:4000",
            "192.168.1.2:0",
            "224.0.0.1:4000",
            "pas une adresse",
            "192.168.1.2:4000",
        ]
        .map(String::from);
        assert_eq!(
            parse_candidates(&list, local),
            vec![
                "203.0.113.7:4000".parse::<SocketAddr>().unwrap(),
                "192.168.1.2:4000".parse().unwrap()
            ]
        );
    }

    #[test]
    fn local_addrs_exclude_loopback() {
        let like: SocketAddr = "0.0.0.0:0".parse().unwrap();
        for a in local_addrs(like, 1234) {
            let a: SocketAddr = a.parse().unwrap();
            assert!(!a.ip().is_loopback());
            assert!(a.is_ipv4());
            assert_eq!(a.port(), 1234);
        }
    }
}
