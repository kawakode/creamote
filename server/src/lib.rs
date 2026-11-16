//! Serveur Creamote : rendezvous et relay.
//!
//! Un seul endpoint QUIC sert les deux rôles. Le premier message de chaque
//! flux indique son rôle :
//! - `RegisterPeer` ouvre un **flux de contrôle** : le pair prouve qu'il
//!   possède sa clé d'identité, puis échange demandes, offres et jetons ;
//! - `RelayJoin` ouvre un **flux relay** : une fois les deux pairs présents
//!   avec leur jeton, le serveur recopie les octets de l'un à l'autre sans
//!   les interpréter (ils sont chiffrés de bout en bout par Noise).
//!
//! En mode public (serveur officiel), la [`Policy`] limite le nombre de
//! sessions relay simultanées, leur durée et leur débit, ainsi que les
//! connexions, enregistrements et demandes de session par adresse IP
//! ([`ratelimit`]). Les compteurs sont exposés par [`metrics`].
//!
//! La gestion de parc (comptes, entités, parcs, RBAC) est exposée par une API
//! HTTP ([`api`]) adossée à la base de données ([`db`]).

pub mod api;
pub mod auth;
pub mod db;
pub mod limiter;
pub mod metrics;
pub mod oidc;
pub mod ratelimit;
pub mod rbac;
pub mod totp;
pub mod webauthn;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use creamote_crypto::{DeviceId, DeviceIdentity, PublicIdentity};
use creamote_net::tls::{ServerCert, ServerPin};
use creamote_net::{EnrollStatus, RegisterStatus, RejectReason, frame, ident};
use creamote_proto::rendezvous::v1::{
    ConnectAnswer, ConnectOffer, ConnectRejected, ConnectRequest, EnrollRequest, EnrollResponse,
    RegisterPeer, RegisterPeerResponse, RelayGrant, RelayJoin, RendezvousMessage, ServerPolicy,
    rendezvous_message::Kind,
};
use quinn::{RecvStream, SendStream};
use rand_core::{OsRng, RngCore};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::JoinHandle;

use metrics::Metrics;
use ratelimit::{IpCounts, IpGuard};

type SessionId = [u8; 16];
type Token = [u8; 32];
type Pipe = (RecvStream, SendStream);

/// Délai pour envoyer le premier message d'un flux.
const FIRST_MESSAGE_TIMEOUT: Duration = Duration::from_secs(10);
/// Durée de vie d'une offre sans réponse.
const OFFER_TTL: Duration = Duration::from_secs(60);
/// Fichier de la clé qui signe les tickets de session.
const TICKET_KEY_FILE: &str = "ticket-signing.key";

/// Limites appliquées par le serveur.
#[derive(Debug, Clone)]
pub struct Policy {
    pub public_mode: bool,
    /// Sessions relay simultanées, 0 = illimité.
    pub max_relay_sessions: u32,
    /// Sessions relay simultanées par adresse IP du demandeur, 0 = illimité.
    pub max_relay_sessions_per_ip: u32,
    /// Durée maximale d'une session relay, 0 = illimitée.
    pub max_relay_seconds: u32,
    /// Débit maximal d'une session relay, par sens, en bit/s, 0 = illimité.
    pub max_relay_bitrate_bps: u64,
    /// Délai laissé aux deux pairs pour rejoindre le relay.
    pub relay_join_timeout: Duration,
    /// Connexions QUIC simultanées par adresse IP (/64 en IPv6), 0 = illimité.
    pub max_connections_per_ip: u32,
    /// Enregistrements de pairs par adresse IP et par minute, 0 = illimité.
    pub registrations_per_ip_per_minute: u32,
    /// Demandes de session par adresse IP et par minute, 0 = illimité.
    /// Empêche aussi de balayer les ID pour trouver ceux qui sont en ligne.
    pub connect_requests_per_ip_per_minute: u32,
}

impl Policy {
    /// Serveur auto-hébergé : pas de limite.
    pub fn private() -> Self {
        Self {
            public_mode: false,
            max_relay_sessions: 0,
            max_relay_sessions_per_ip: 0,
            max_relay_seconds: 0,
            max_relay_bitrate_bps: 0,
            relay_join_timeout: Duration::from_secs(30),
            max_connections_per_ip: 0,
            registrations_per_ip_per_minute: 0,
            connect_requests_per_ip_per_minute: 0,
        }
    }

    /// Serveur officiel : une session relay à la fois par IP, 10 minutes
    /// maximum, 5 Mbit/s par sens, 200 sessions au total ; 32 connexions,
    /// 20 enregistrements et 30 demandes de session par minute et par IP.
    /// Valeurs ajustables.
    pub fn public() -> Self {
        Self {
            public_mode: true,
            max_relay_sessions: 200,
            max_relay_sessions_per_ip: 1,
            max_relay_seconds: 10 * 60,
            max_relay_bitrate_bps: 5_000_000,
            relay_join_timeout: Duration::from_secs(30),
            max_connections_per_ip: 32,
            registrations_per_ip_per_minute: 20,
            connect_requests_per_ip_per_minute: 30,
        }
    }

    fn to_proto(&self) -> ServerPolicy {
        ServerPolicy {
            public_mode: self.public_mode,
            max_concurrent_relay_sessions: self.max_relay_sessions,
            max_relay_session_seconds: self.max_relay_seconds,
            max_relay_bitrate_bps: self.max_relay_bitrate_bps,
            max_relay_sessions_per_ip: self.max_relay_sessions_per_ip,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub listen: SocketAddr,
    /// Dossier du certificat ; `None` = certificat éphémère (tests).
    pub data_dir: Option<PathBuf>,
    /// Adresse du relay annoncée aux pairs ; `None` = celle du rendezvous.
    pub relay_addr: Option<String>,
    pub policy: Policy,
    /// Base de la gestion de parc ; `None` = pas de gestion de parc (cas du
    /// serveur officiel).
    pub database_url: Option<String>,
    /// Adresse d'écoute HTTP de l'API de gestion (exige `database_url`).
    pub api_listen: Option<SocketAddr>,
    /// L'API est derrière un reverse proxy : l'adresse du client est lue dans
    /// `X-Forwarded-For` (limitation des tentatives de connexion, audit).
    pub trust_forwarded_for: bool,
    /// Connexion OpenID Connect à la console et à l'API.
    pub oidc: Option<oidc::OidcConfig>,
    /// URL publique de la console (`https://admin.example.org`) : domaine
    /// auquel sont liées les clés de sécurité WebAuthn. Sans elle, les clés
    /// ne sont utilisables que si l'API écoute sur une adresse locale
    /// (console ouverte sur `http://localhost:<port>`).
    pub public_url: Option<String>,
}

/// Serveur démarré.
pub struct Server {
    endpoint: quinn::Endpoint,
    pin: ServerPin,
    task: JoinHandle<()>,
    api: Option<(SocketAddr, JoinHandle<()>)>,
    db: Option<db::Db>,
    state: Arc<State>,
}

impl Server {
    pub async fn start(config: Config) -> anyhow::Result<Self> {
        let cert = match &config.data_dir {
            Some(dir) => ServerCert::load_or_generate(dir)?,
            None => ServerCert::generate()?,
        };
        let pin = cert.pin();
        let db = match &config.database_url {
            Some(url) => Some(db::Db::connect(url).await?),
            None => None,
        };
        // Clé de signature des tickets : persistante à côté du certificat.
        let ticket_key = match (&db, &config.data_dir) {
            (None, _) => None,
            (Some(_), Some(dir)) => {
                std::fs::create_dir_all(dir)?;
                Some(Arc::new(
                    creamote_crypto::store::load_or_create(&dir.join(TICKET_KEY_FILE))?.0,
                ))
            }
            (Some(_), None) => Some(Arc::new(DeviceIdentity::generate())),
        };
        let endpoint = quinn::Endpoint::server(cert.quic_server_config()?, config.listen)?;

        let server_address = config.relay_addr.clone();
        let permits = (config.policy.max_relay_sessions > 0)
            .then(|| Arc::new(Semaphore::new(config.policy.max_relay_sessions as usize)));
        let minute = Duration::from_secs(60);
        let state = Arc::new(State {
            relay_addr: config.relay_addr.unwrap_or_default(),
            registrations: ratelimit::WindowLimiter::new(
                config.policy.registrations_per_ip_per_minute,
                minute,
            ),
            requests: ratelimit::WindowLimiter::new(
                config.policy.connect_requests_per_ip_per_minute,
                minute,
            ),
            connections: ratelimit::IpCounts::default(),
            metrics: metrics::Metrics::default(),
            policy: config.policy,
            permits,
            db: db.clone(),
            ticket_key: ticket_key.clone(),
            peers: Mutex::default(),
            pending: Mutex::default(),
            relays: Mutex::default(),
            ip_sessions: IpCounts::default(),
            next_conn: AtomicU64::new(1),
        });

        let api = match (config.api_listen, &db, ticket_key) {
            (Some(addr), Some(db), Some(ticket_key)) => {
                let listener = tokio::net::TcpListener::bind(addr).await?;
                let local = listener.local_addr()?;
                let st = state.clone();
                let online: api::Online = Arc::new(move |key: &[u8; 32]| st.is_online(key));
                let rp = match &config.public_url {
                    Some(url) => Some(
                        webauthn::RelyingParty::from_url(url).map_err(|e| anyhow::anyhow!(e))?,
                    ),
                    None if local.ip().is_loopback() => Some(
                        webauthn::RelyingParty::from_url(&format!(
                            "http://localhost:{}",
                            local.port()
                        ))
                        .map_err(|e| anyhow::anyhow!(e))?,
                    ),
                    None => None,
                };
                let app = api::router(
                    db.clone(),
                    api::Services {
                        ticket_key,
                        online,
                        server_pin: pin.to_string(),
                        server_address: server_address.clone(),
                        trust_forwarded_for: config.trust_forwarded_for,
                        login_limits: Default::default(),
                        oidc: match &config.oidc {
                            Some(c) => Some(Arc::new(oidc::Oidc::new(c.clone())?)),
                            None => None,
                        },
                        webauthn: rp.map(|rp| Arc::new(webauthn::WebAuthn::new(rp))),
                    },
                );
                let task = tokio::spawn(async move {
                    if let Err(e) = axum::serve(
                        listener,
                        app.into_make_service_with_connect_info::<SocketAddr>(),
                    )
                    .await
                    {
                        tracing::error!("API HTTP arrêtée : {e}");
                    }
                });
                Some((local, task))
            }
            (Some(_), _, _) => anyhow::bail!("l'API de gestion exige une base de données"),
            _ => None,
        };

        let ep = endpoint.clone();
        let st = state.clone();
        let task = tokio::spawn(async move {
            while let Some(incoming) = ep.accept().await {
                let ip = incoming.remote_address().ip();
                let max = st.policy.max_connections_per_ip;
                let Ok(guard) = st.connections.acquire(ip, max) else {
                    Metrics::inc(&st.metrics.connections_refused_total);
                    incoming.refuse();
                    continue;
                };
                let state = st.clone();
                Metrics::inc(&st.metrics.connections_total);
                tokio::spawn(async move {
                    Metrics::inc(&state.metrics.connections_active);
                    if let Err(e) = handle_connection(state.clone(), incoming).await {
                        tracing::debug!("connexion terminée : {e}");
                    }
                    Metrics::dec(&state.metrics.connections_active);
                    drop(guard);
                });
            }
        });
        Ok(Self {
            endpoint,
            pin,
            task,
            api,
            db,
            state,
        })
    }

    /// Adresse de l'API HTTP, si elle est active.
    pub fn api_addr(&self) -> Option<SocketAddr> {
        self.api.as_ref().map(|(a, _)| *a)
    }

    pub fn db(&self) -> Option<&db::Db> {
        self.db.as_ref()
    }

    /// Compteurs au format texte de Prometheus.
    pub fn metrics_text(&self) -> String {
        let peers = self.state.peers.lock().expect("verrou sain").len();
        self.state.metrics.render(peers)
    }

    /// Fonction qui produit les compteurs, à servir sur HTTP.
    pub fn metrics_source(&self) -> Arc<dyn Fn() -> String + Send + Sync> {
        let state = self.state.clone();
        Arc::new(move || {
            let peers = state.peers.lock().expect("verrou sain").len();
            state.metrics.render(peers)
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// Empreinte à communiquer aux clients.
    pub fn pin(&self) -> ServerPin {
        self.pin
    }

    pub async fn shutdown(self) {
        self.endpoint.close(0u32.into(), b"arret");
        self.task.abort();
        if let Some((_, task)) = self.api {
            task.abort();
        }
        self.endpoint.wait_idle().await;
    }
}

struct Peer {
    identity: PublicIdentity,
    tx: mpsc::Sender<RendezvousMessage>,
    conn_id: u64,
    /// Adresses candidates pour la connexion directe (observée puis LAN),
    /// vide si le pair est `relay_only`.
    addrs: Vec<String>,
}

struct Pending {
    host: DeviceId,
    viewer_ip: IpAddr,
    viewer_addrs: Vec<String>,
    viewer_tx: mpsc::Sender<RendezvousMessage>,
    request_id: u64,
    created: tokio::time::Instant,
}

struct RelaySlot {
    tokens: [Token; 2],
    waiting: Option<(usize, Pipe)>,
    quota: Quota,
}

/// Places occupées par une session relay (globale et par IP), libérées
/// automatiquement à la fin de la session ou à l'expiration du créneau.
struct Quota {
    _global: Option<OwnedSemaphorePermit>,
    _ip: Option<IpGuard>,
    metrics: Option<Arc<State>>,
}

impl Drop for Quota {
    fn drop(&mut self) {
        if let Some(st) = &self.metrics {
            Metrics::dec(&st.metrics.relay_sessions_active);
        }
    }
}

struct State {
    policy: Policy,
    relay_addr: String,
    permits: Option<Arc<Semaphore>>,
    db: Option<db::Db>,
    ticket_key: Option<Arc<DeviceIdentity>>,
    peers: Mutex<HashMap<DeviceId, Peer>>,
    pending: Mutex<HashMap<SessionId, Pending>>,
    relays: Mutex<HashMap<SessionId, RelaySlot>>,
    ip_sessions: IpCounts,
    next_conn: AtomicU64,
    connections: IpCounts,
    registrations: ratelimit::WindowLimiter,
    requests: ratelimit::WindowLimiter,
    metrics: Metrics,
}

impl State {
    /// La machine de clé `key` a-t-elle un flux de contrôle ouvert ?
    fn is_online(&self, key: &[u8; 32]) -> bool {
        self.peers
            .lock()
            .expect("verrou sain")
            .get(&DeviceId::from_signing_key(key))
            .is_some_and(|p| p.identity.signing_key() == key)
    }
}

fn msg(kind: Kind) -> RendezvousMessage {
    RendezvousMessage { kind: Some(kind) }
}

fn reject(tx: &mpsc::Sender<RendezvousMessage>, request_id: u64, reason: RejectReason) {
    let _ = tx.try_send(msg(Kind::ConnectRejected(ConnectRejected {
        request_id,
        reason: reason as i32,
    })));
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

/// Comparaison en temps constant de deux jetons.
fn token_eq(a: &[u8], b: &Token) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn handle_connection(state: Arc<State>, incoming: quinn::Incoming) -> anyhow::Result<()> {
    let conn = incoming.await?;
    let conn_id = state.next_conn.fetch_add(1, Ordering::Relaxed);
    loop {
        let (send, mut recv) = conn.accept_bi().await?;
        let state = state.clone();
        let conn = conn.clone();
        tokio::spawn(async move {
            let first =
                tokio::time::timeout(FIRST_MESSAGE_TIMEOUT, frame::read_msg(&mut recv)).await;
            let result = match first {
                Ok(Ok(Some(RendezvousMessage {
                    kind: Some(Kind::RegisterPeer(reg)),
                }))) => control_stream(state, conn, conn_id, send, recv, reg).await,
                Ok(Ok(Some(RendezvousMessage {
                    kind: Some(Kind::RelayJoin(join)),
                }))) => {
                    relay_join(state, send, recv, join);
                    Ok(())
                }
                _ => Ok(()),
            };
            if let Err(e) = result {
                tracing::debug!("flux terminé : {e}");
            }
        });
    }
}

async fn control_stream(
    state: Arc<State>,
    conn: quinn::Connection,
    conn_id: u64,
    mut send: SendStream,
    mut recv: RecvStream,
    reg: RegisterPeer,
) -> anyhow::Result<()> {
    let respond = |status: RegisterStatus, device_id: String| RegisterPeerResponse {
        status: status as i32,
        device_id,
        observed_addr: conn.remote_address().to_string(),
        policy: Some(state.policy.to_proto()),
    };

    if !state.registrations.allow(conn.remote_address().ip()) {
        Metrics::inc(&state.metrics.registrations_rate_limited_total);
        let r = respond(RegisterStatus::RateLimited, String::new());
        frame::write_msg(&mut send, &msg(Kind::RegisterPeerResponse(r))).await?;
        return Ok(());
    }
    let identity = reg
        .identity
        .as_ref()
        .and_then(|p| ident::from_proto(p).ok())
        .filter(|id| ident::verify_register_proof(&conn, id, &reg.proof).unwrap_or(false));
    let Some(identity) = identity else {
        let r = respond(RegisterStatus::InvalidProof, String::new());
        frame::write_msg(&mut send, &msg(Kind::RegisterPeerResponse(r))).await?;
        return Ok(());
    };
    let device_id = identity.device_id();
    let addrs = candidates(&conn, &reg);

    let (tx, mut rx) = mpsc::channel::<RendezvousMessage>(32);
    let conflict = {
        let mut peers = state.peers.lock().expect("verrou sain");
        // Une même identité qui se reconnecte remplace l'ancienne connexion ;
        // une autre clé ayant le même ID court est refusée.
        let conflict = peers
            .get(&device_id)
            .is_some_and(|existing| existing.identity != identity);
        if !conflict {
            peers.insert(
                device_id,
                Peer {
                    identity: identity.clone(),
                    tx: tx.clone(),
                    conn_id,
                    addrs: addrs.clone(),
                },
            );
        }
        conflict
    };
    if conflict {
        let r = respond(RegisterStatus::IdConflict, device_id.to_string());
        frame::write_msg(&mut send, &msg(Kind::RegisterPeerResponse(r))).await?;
        return Ok(());
    }
    tracing::info!(%device_id, addr = %conn.remote_address(), "pair enregistré");
    Metrics::inc(&state.metrics.registrations_total);

    let r = respond(RegisterStatus::Ok, device_id.to_string());
    frame::write_msg(&mut send, &msg(Kind::RegisterPeerResponse(r))).await?;
    if let Some(db) = &state.db {
        if let Err(e) = db.touch_device(&auth::hex(identity.signing_key())).await {
            tracing::warn!("mise à jour de last_seen impossible : {e}");
        }
    }
    let platform = platform_name(reg.platform());

    let writer = tokio::spawn(async move {
        while let Some(m) = rx.recv().await {
            if frame::write_msg(&mut send, &m).await.is_err() {
                break;
            }
        }
    });

    while let Ok(Some(m)) = frame::read_msg::<_, RendezvousMessage>(&mut recv).await {
        match m.kind {
            Some(Kind::ConnectRequest(req)) => {
                handle_request(&state, &identity, &conn, &addrs, &tx, req);
            }
            Some(Kind::ConnectAnswer(ans)) => handle_answer(&state, device_id, &tx, ans),
            Some(Kind::EnrollRequest(req)) => {
                let r = handle_enroll(&state, &identity, platform, req).await;
                let _ = tx.send(msg(Kind::EnrollResponse(r))).await;
            }
            _ => tracing::debug!(%device_id, "message inattendu ignoré"),
        }
    }

    writer.abort();
    let mut peers = state.peers.lock().expect("verrou sain");
    if peers.get(&device_id).is_some_and(|p| p.conn_id == conn_id) {
        peers.remove(&device_id);
        tracing::info!(%device_id, "pair déconnecté");
    }
    Ok(())
}

/// Adresses candidates d'un pair : celle observée par le serveur, puis ses
/// adresses LAN annoncées (validées, au plus 8 au total).
fn candidates(conn: &quinn::Connection, reg: &RegisterPeer) -> Vec<String> {
    if reg.relay_only {
        return Vec::new();
    }
    let mut out = vec![conn.remote_address()];
    for a in &reg.local_addrs {
        let Ok(addr) = a.parse::<SocketAddr>() else {
            continue;
        };
        let ip = addr.ip();
        if addr.port() == 0 || ip.is_unspecified() || ip.is_multicast() || out.contains(&addr) {
            continue;
        }
        out.push(addr);
        if out.len() == creamote_net::p2p::MAX_CANDIDATES {
            break;
        }
    }
    out.iter().map(SocketAddr::to_string).collect()
}

fn platform_name(p: creamote_proto::common::v1::Platform) -> &'static str {
    use creamote_proto::common::v1::Platform;
    match p {
        Platform::Windows => "windows",
        Platform::Macos => "macos",
        Platform::Linux => "linux",
        Platform::Android => "android",
        Platform::Unspecified => "unknown",
    }
}

async fn handle_enroll(
    state: &State,
    identity: &PublicIdentity,
    platform: &str,
    req: EnrollRequest,
) -> EnrollResponse {
    let reply = |status: EnrollStatus| EnrollResponse {
        status: status as i32,
        ..Default::default()
    };
    let (Some(db), Some(key)) = (&state.db, &state.ticket_key) else {
        return reply(EnrollStatus::Unavailable);
    };
    let device_id = identity.device_id();
    let name: String = req.name.trim().chars().take(200).collect();
    let name = if name.is_empty() {
        device_id.to_string()
    } else {
        name
    };
    let outcome = db
        .enroll_device(
            &req.token,
            &auth::hex(identity.signing_key()),
            &format!("{:09}", device_id.as_u32()),
            &name,
            platform,
        )
        .await;
    match outcome {
        Ok(db::Enrollment::Enrolled {
            device_row_id,
            entity_id,
            entity_name,
            fleet_name,
        }) => {
            tracing::info!(%device_id, entity = %entity_id, "machine enrôlée");
            let detail = serde_json::json!({ "device_id": device_id.to_string(), "name": name });
            if let Err(e) = db
                .audit(
                    Some(&entity_id),
                    None,
                    "device.enroll",
                    &device_row_id,
                    detail,
                )
                .await
            {
                tracing::warn!("audit impossible : {e}");
            }
            EnrollResponse {
                status: EnrollStatus::Ok as i32,
                entity_name,
                fleet_name,
                ticket_public_key: key.public().signing_key().to_vec(),
            }
        }
        Ok(db::Enrollment::InvalidToken) => reply(EnrollStatus::InvalidToken),
        Ok(db::Enrollment::AlreadyEnrolled) => reply(EnrollStatus::AlreadyEnrolled),
        Err(e) => {
            tracing::error!("enrôlement : {e}");
            reply(EnrollStatus::Unavailable)
        }
    }
}

fn handle_request(
    state: &State,
    viewer: &PublicIdentity,
    conn: &quinn::Connection,
    viewer_addrs: &[String],
    viewer_tx: &mpsc::Sender<RendezvousMessage>,
    req: ConnectRequest,
) {
    Metrics::inc(&state.metrics.connect_requests_total);
    if !state.requests.allow(conn.remote_address().ip()) {
        Metrics::inc(&state.metrics.connect_requests_rate_limited_total);
        return reject(viewer_tx, req.request_id, RejectReason::RateLimited);
    }
    let Some(target) = DeviceId::parse(&req.target_device_id) else {
        return reject(viewer_tx, req.request_id, RejectReason::InvalidRequest);
    };
    let host_tx = {
        let peers = state.peers.lock().expect("verrou sain");
        match peers.get(&target) {
            Some(p) => p.tx.clone(),
            None => {
                Metrics::inc(&state.metrics.sessions_target_offline_total);
                return reject(viewer_tx, req.request_id, RejectReason::TargetOffline);
            }
        }
    };

    let session_id: SessionId = random();
    {
        let mut pending = state.pending.lock().expect("verrou sain");
        pending.retain(|_, p| p.created.elapsed() < OFFER_TTL);
        pending.insert(
            session_id,
            Pending {
                host: target,
                viewer_ip: conn.remote_address().ip(),
                viewer_addrs: viewer_addrs.to_vec(),
                viewer_tx: viewer_tx.clone(),
                request_id: req.request_id,
                created: tokio::time::Instant::now(),
            },
        );
    }
    let offer = ConnectOffer {
        session_id: session_id.to_vec(),
        requester: Some(ident::to_proto(viewer)),
        requester_observed_addr: viewer_addrs.first().cloned().unwrap_or_default(),
        requester_local_addrs: viewer_addrs.iter().skip(1).cloned().collect(),
        session_ticket: req.session_ticket,
    };
    if host_tx.try_send(msg(Kind::ConnectOffer(offer))).is_err() {
        state
            .pending
            .lock()
            .expect("verrou sain")
            .remove(&session_id);
        reject(viewer_tx, req.request_id, RejectReason::TargetOffline);
    }
}

fn handle_answer(
    state: &Arc<State>,
    host: DeviceId,
    host_tx: &mpsc::Sender<RendezvousMessage>,
    ans: ConnectAnswer,
) {
    let Ok(session_id) = SessionId::try_from(ans.session_id.as_slice()) else {
        return;
    };
    let pending = {
        let mut map = state.pending.lock().expect("verrou sain");
        match map.get(&session_id) {
            Some(p) if p.host == host => map.remove(&session_id),
            _ => None,
        }
    };
    let Some(p) = pending else { return };

    if !ans.accepted {
        Metrics::inc(&state.metrics.sessions_declined_total);
        return reject(&p.viewer_tx, p.request_id, RejectReason::Declined);
    }
    // Connexion directe possible si aucun des deux pairs n'est relay_only.
    let host_addrs = state
        .peers
        .lock()
        .expect("verrou sain")
        .get(&host)
        .map(|peer| peer.addrs.clone())
        .unwrap_or_default();
    let direct = !host_addrs.is_empty() && !p.viewer_addrs.is_empty();
    let (viewer_peer, host_peer) = if direct {
        (host_addrs, p.viewer_addrs.clone())
    } else {
        (Vec::new(), Vec::new())
    };

    let grant = |token: Option<&Token>,
                 request_id: u64,
                 peer_addrs: Vec<String>,
                 unavailable: RejectReason| {
        msg(Kind::RelayGrant(RelayGrant {
            session_id: session_id.to_vec(),
            relay_addr: if token.is_some() {
                state.relay_addr.clone()
            } else {
                String::new()
            },
            relay_token: token.map(|t| t.to_vec()).unwrap_or_default(),
            expires_in_seconds: state.policy.relay_join_timeout.as_secs() as u32,
            request_id,
            max_session_seconds: state.policy.max_relay_seconds,
            peer_addrs,
            relay_unavailable: unavailable as i32,
        }))
    };

    let quota = match relay_quota(state, &p) {
        Ok(quota) => quota,
        // Relay indisponible : la session peut encore aboutir en direct, qui
        // ne coûte rien au serveur.
        Err(reason) if direct => {
            Metrics::inc(&state.metrics.sessions_direct_only_total);
            let _ = p
                .viewer_tx
                .try_send(grant(None, p.request_id, viewer_peer, reason));
            let _ = host_tx.try_send(grant(None, 0, host_peer, reason));
            return;
        }
        Err(reason) => return reject(&p.viewer_tx, p.request_id, reason),
    };

    let tokens: [Token; 2] = [random(), random()];
    state.relays.lock().expect("verrou sain").insert(
        session_id,
        RelaySlot {
            tokens,
            waiting: None,
            quota,
        },
    );
    // Libère le créneau si les deux pairs ne se présentent pas à temps.
    let st = state.clone();
    let timeout = state.policy.relay_join_timeout;
    tokio::spawn(async move {
        tokio::time::sleep(timeout).await;
        st.relays.lock().expect("verrou sain").remove(&session_id);
    });

    let none = RejectReason::Unspecified;
    let _ = p
        .viewer_tx
        .try_send(grant(Some(&tokens[0]), p.request_id, viewer_peer, none));
    let _ = host_tx.try_send(grant(Some(&tokens[1]), 0, host_peer, none));
}

/// Réserve une place sur le relay (quota par IP, puis global).
fn relay_quota(state: &State, p: &Pending) -> Result<Quota, RejectReason> {
    let max = state.policy.max_relay_sessions_per_ip;
    let Ok(ip) = state.ip_sessions.acquire(p.viewer_ip, max) else {
        tracing::info!(ip = %p.viewer_ip, "quota de sessions relay atteint pour cette IP");
        Metrics::inc(&state.metrics.relay_quota_exceeded_total);
        return Err(RejectReason::QuotaExceeded);
    };
    let global = match &state.permits {
        Some(sem) => match sem.clone().try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => {
                tracing::warn!("relay plein");
                Metrics::inc(&state.metrics.relay_full_total);
                return Err(RejectReason::RelayFull);
            }
        },
        None => None,
    };
    Ok(Quota {
        _global: global,
        _ip: ip,
        metrics: None,
    })
}

fn relay_join(state: Arc<State>, send: SendStream, recv: RecvStream, join: RelayJoin) {
    let Ok(session_id) = SessionId::try_from(join.session_id.as_slice()) else {
        return;
    };
    let pipe = (recv, send);
    let paired = {
        let mut relays = state.relays.lock().expect("verrou sain");
        let Some(slot) = relays.get_mut(&session_id) else {
            return;
        };
        let Some(side) = slot
            .tokens
            .iter()
            .position(|t| token_eq(&join.relay_token, t))
        else {
            return;
        };
        match slot.waiting.take() {
            Some((other_side, other)) if other_side != side => {
                let mut slot = relays.remove(&session_id).expect("présent");
                slot.quota.metrics = Some(state.clone());
                Some((other, pipe, slot.quota))
            }
            Some(first) => {
                // Même côté présenté deux fois : on garde le premier.
                slot.waiting = Some(first);
                None
            }
            None => {
                slot.waiting = Some((side, pipe));
                None
            }
        }
    };
    if let Some((a, b, quota)) = paired {
        Metrics::inc(&state.metrics.relay_sessions_total);
        Metrics::inc(&state.metrics.relay_sessions_active);
        tokio::spawn(pump(state, a, b, quota));
    }
}

async fn pump(state: Arc<State>, a: Pipe, b: Pipe, quota: Quota) {
    tracing::info!("session relay ouverte");
    let bps = state.policy.max_relay_bitrate_bps;
    let (a_recv, a_send) = a;
    let (b_recv, b_send) = b;
    let copy = async {
        tokio::try_join!(
            copy_limited(a_recv, b_send, bps, &state.metrics),
            copy_limited(b_recv, a_send, bps, &state.metrics),
        )
    };
    let outcome = match state.policy.max_relay_seconds {
        0 => copy.await,
        max => match tokio::time::timeout(Duration::from_secs(max.into()), copy).await {
            Ok(r) => r,
            Err(_) => {
                tracing::info!("session relay coupée : durée maximale atteinte");
                Metrics::inc(&state.metrics.relay_sessions_expired_total);
                drop(quota);
                return;
            }
        },
    };
    match outcome {
        Ok((ab, ba)) => tracing::info!(
            octets_aller = ab,
            octets_retour = ba,
            "session relay fermée"
        ),
        Err(e) => tracing::info!("session relay interrompue : {e}"),
    }
    drop(quota);
}

/// Taille des lectures du relay.
const RELAY_CHUNK: usize = 32 * 1024;

/// Recopie un sens d'une session relay, au plus `bps` bit/s (0 = sans
/// limite). Les octets en attente restent dans le tampon de réception QUIC
/// de la source : le contrôle de flux ralentit l'émetteur, dont le débit
/// adaptatif (M3) voit monter la file d'attente et baisse le débit vidéo.
async fn copy_limited(
    mut from: RecvStream,
    mut to: SendStream,
    bps: u64,
    metrics: &Metrics,
) -> std::io::Result<u64> {
    let mut bucket = (bps > 0).then(|| TokenBucket::new(bps / 8));
    let mut buf = vec![0u8; RELAY_CHUNK];
    let mut total = 0u64;
    while let Some(n) = from.read(&mut buf).await.map_err(std::io::Error::other)? {
        if let Some(b) = bucket.as_mut() {
            b.take(n as u64).await;
        }
        to.write_all(&buf[..n])
            .await
            .map_err(std::io::Error::other)?;
        total += n as u64;
        metrics
            .relay_bytes_total
            .fetch_add(n as u64, Ordering::Relaxed);
    }
    let _ = to.finish();
    Ok(total)
}

/// Seau à jetons : `rate` octets par seconde, avec une rafale de 250 ms.
struct TokenBucket {
    rate: u64,
    /// Instant où le seau sera de nouveau à zéro (dans le passé = plein).
    debt_until: Instant,
}

impl TokenBucket {
    const BURST: Duration = Duration::from_millis(250);

    fn new(rate: u64) -> Self {
        Self {
            rate: rate.max(1),
            debt_until: Instant::now(),
        }
    }

    /// Délai à attendre avant d'envoyer `n` octets reçus à `now`.
    fn reserve(&mut self, n: u64, now: Instant) -> Duration {
        let cost = Duration::from_secs_f64(n as f64 / self.rate as f64);
        let start = self
            .debt_until
            .max(now.checked_sub(Self::BURST).unwrap_or(now));
        self.debt_until = start + cost;
        self.debt_until
            .saturating_duration_since(now)
            .saturating_sub(Self::BURST)
    }

    async fn take(&mut self, n: u64) {
        let wait = self.reserve(n, Instant::now());
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_bucket_allows_burst_then_paces() {
        let t0 = Instant::now() + Duration::from_secs(10);
        let mut b = TokenBucket {
            rate: 1000,
            debt_until: t0,
        };
        // Rafale de 250 ms (250 octets) sans attente.
        assert_eq!(b.reserve(250, t0), Duration::ZERO);
        // Au-delà, 1 ms par octet.
        assert_eq!(b.reserve(100, t0), Duration::from_millis(100));
        // Une seconde plus tard, la dette est remboursée.
        let t1 = t0 + Duration::from_secs(2);
        assert_eq!(b.reserve(200, t1), Duration::ZERO);
    }
}
