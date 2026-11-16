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
//! sessions relay simultanées et leur durée.
//!
//! La gestion de parc (comptes, entités, parcs, RBAC) est exposée par une API
//! HTTP ([`api`]) adossée à la base de données ([`db`]).

pub mod api;
pub mod auth;
pub mod db;
pub mod rbac;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
use tokio::io::Join;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::JoinHandle;

type SessionId = [u8; 16];
type Token = [u8; 32];
type Pipe = Join<RecvStream, SendStream>;

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
    /// Délai laissé aux deux pairs pour rejoindre le relay.
    pub relay_join_timeout: Duration,
}

impl Policy {
    /// Serveur auto-hébergé : pas de limite.
    pub fn private() -> Self {
        Self {
            public_mode: false,
            max_relay_sessions: 0,
            max_relay_sessions_per_ip: 0,
            max_relay_seconds: 0,
            relay_join_timeout: Duration::from_secs(30),
        }
    }

    /// Serveur officiel : une session relay à la fois par IP, 10 minutes
    /// maximum, 200 sessions au total. Valeurs ajustables.
    pub fn public() -> Self {
        Self {
            public_mode: true,
            max_relay_sessions: 200,
            max_relay_sessions_per_ip: 1,
            max_relay_seconds: 10 * 60,
            relay_join_timeout: Duration::from_secs(30),
        }
    }

    fn to_proto(&self) -> ServerPolicy {
        ServerPolicy {
            public_mode: self.public_mode,
            max_concurrent_relay_sessions: self.max_relay_sessions,
            max_relay_session_seconds: self.max_relay_seconds,
            max_relay_bitrate_bps: 0,
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
}

/// Serveur démarré.
pub struct Server {
    endpoint: quinn::Endpoint,
    pin: ServerPin,
    task: JoinHandle<()>,
    api: Option<(SocketAddr, JoinHandle<()>)>,
    db: Option<db::Db>,
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

        let permits = (config.policy.max_relay_sessions > 0)
            .then(|| Arc::new(Semaphore::new(config.policy.max_relay_sessions as usize)));
        let state = Arc::new(State {
            relay_addr: config.relay_addr.unwrap_or_default(),
            policy: config.policy,
            permits,
            db: db.clone(),
            ticket_key: ticket_key.clone(),
            peers: Mutex::default(),
            pending: Mutex::default(),
            relays: Mutex::default(),
            ip_sessions: Arc::default(),
            next_conn: AtomicU64::new(1),
        });

        let api = match (config.api_listen, &db, ticket_key) {
            (Some(addr), Some(db), Some(ticket_key)) => {
                let listener = tokio::net::TcpListener::bind(addr).await?;
                let local = listener.local_addr()?;
                let st = state.clone();
                let online: api::Online = Arc::new(move |key: &[u8; 32]| st.is_online(key));
                let app = api::router(db.clone(), ticket_key, online);
                let task = tokio::spawn(async move {
                    if let Err(e) = axum::serve(listener, app).await {
                        tracing::error!("API HTTP arrêtée : {e}");
                    }
                });
                Some((local, task))
            }
            (Some(_), _, _) => anyhow::bail!("l'API de gestion exige une base de données"),
            _ => None,
        };

        let ep = endpoint.clone();
        let task = tokio::spawn(async move {
            while let Some(incoming) = ep.accept().await {
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(state, incoming).await {
                        tracing::debug!("connexion terminée : {e}");
                    }
                });
            }
        });
        Ok(Self {
            endpoint,
            pin,
            task,
            api,
            db,
        })
    }

    /// Adresse de l'API HTTP, si elle est active.
    pub fn api_addr(&self) -> Option<SocketAddr> {
        self.api.as_ref().map(|(a, _)| *a)
    }

    pub fn db(&self) -> Option<&db::Db> {
        self.db.as_ref()
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
}

struct Pending {
    host: DeviceId,
    viewer_ip: IpAddr,
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
}

type IpCounts = Arc<Mutex<HashMap<IpAddr, u32>>>;

struct IpGuard {
    counts: IpCounts,
    ip: IpAddr,
}

impl IpGuard {
    fn acquire(counts: &IpCounts, ip: IpAddr, max: u32) -> Option<Self> {
        let mut map = counts.lock().expect("verrou sain");
        let n = map.entry(ip).or_insert(0);
        if *n >= max {
            return None;
        }
        *n += 1;
        Some(Self {
            counts: counts.clone(),
            ip,
        })
    }
}

impl Drop for IpGuard {
    fn drop(&mut self) {
        let mut map = self.counts.lock().expect("verrou sain");
        if let Some(n) = map.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                map.remove(&self.ip);
            }
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
                handle_request(&state, &identity, &conn, &tx, req);
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
    viewer_tx: &mpsc::Sender<RendezvousMessage>,
    req: ConnectRequest,
) {
    let Some(target) = DeviceId::parse(&req.target_device_id) else {
        return reject(viewer_tx, req.request_id, RejectReason::InvalidRequest);
    };
    let host_tx = {
        let peers = state.peers.lock().expect("verrou sain");
        match peers.get(&target) {
            Some(p) => p.tx.clone(),
            None => return reject(viewer_tx, req.request_id, RejectReason::TargetOffline),
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
                viewer_tx: viewer_tx.clone(),
                request_id: req.request_id,
                created: tokio::time::Instant::now(),
            },
        );
    }
    let offer = ConnectOffer {
        session_id: session_id.to_vec(),
        requester: Some(ident::to_proto(viewer)),
        requester_observed_addr: conn.remote_address().to_string(),
        requester_local_addrs: Vec::new(),
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
        return reject(&p.viewer_tx, p.request_id, RejectReason::Declined);
    }
    let ip = match state.policy.max_relay_sessions_per_ip {
        0 => None,
        max => match IpGuard::acquire(&state.ip_sessions, p.viewer_ip, max) {
            Some(guard) => Some(guard),
            None => {
                tracing::info!(ip = %p.viewer_ip, "quota de sessions relay atteint pour cette IP");
                return reject(&p.viewer_tx, p.request_id, RejectReason::QuotaExceeded);
            }
        },
    };
    let global = match &state.permits {
        Some(sem) => match sem.clone().try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => {
                tracing::warn!("relay plein, session refusée");
                return reject(&p.viewer_tx, p.request_id, RejectReason::RelayFull);
            }
        },
        None => None,
    };
    let quota = Quota {
        _global: global,
        _ip: ip,
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

    let grant = |token: &Token, request_id: u64| {
        msg(Kind::RelayGrant(RelayGrant {
            session_id: session_id.to_vec(),
            relay_addr: state.relay_addr.clone(),
            relay_token: token.to_vec(),
            expires_in_seconds: timeout.as_secs() as u32,
            request_id,
            max_session_seconds: state.policy.max_relay_seconds,
        }))
    };
    let _ = p.viewer_tx.try_send(grant(&tokens[0], p.request_id));
    let _ = host_tx.try_send(grant(&tokens[1], 0));
}

fn relay_join(state: Arc<State>, send: SendStream, recv: RecvStream, join: RelayJoin) {
    let Ok(session_id) = SessionId::try_from(join.session_id.as_slice()) else {
        return;
    };
    let pipe = tokio::io::join(recv, send);
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
                let slot = relays.remove(&session_id).expect("présent");
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
        let max = state.policy.max_relay_seconds;
        tokio::spawn(pump(a, b, quota, max));
    }
}

async fn pump(mut a: Pipe, mut b: Pipe, quota: Quota, max_secs: u32) {
    tracing::info!("session relay ouverte");
    let copy = tokio::io::copy_bidirectional(&mut a, &mut b);
    let outcome = if max_secs > 0 {
        match tokio::time::timeout(Duration::from_secs(max_secs.into()), copy).await {
            Ok(r) => r,
            Err(_) => {
                tracing::info!("session relay coupée : durée maximale atteinte");
                drop(quota);
                return;
            }
        }
    } else {
        copy.await
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
