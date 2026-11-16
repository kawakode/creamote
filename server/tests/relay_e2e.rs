//! Tests de bout en bout : serveur réel en mémoire, host et viewer réels.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use creamote_crypto::{DeviceId, DeviceIdentity, PublicIdentity};
use creamote_net::ident;
use creamote_net::relay::RelayStream;
use creamote_net::rendezvous::{Event, RegisterOptions, RendezvousClient};
use creamote_net::secure::SecureChannel;
use creamote_net::tls::ServerPin;
use creamote_net::{NetError, RegisterStatus, RejectReason};
use creamote_server::{Config, Policy, Server};

/// Mode public sans les limites par minute (les tests ouvrent beaucoup de
/// sessions depuis 127.0.0.1).
fn public() -> Policy {
    Policy {
        registrations_per_ip_per_minute: 0,
        connect_requests_per_ip_per_minute: 0,
        ..Policy::public()
    }
}

async fn start(policy: Policy) -> (Server, SocketAddr, ServerPin) {
    let server = Server::start(Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        data_dir: None,
        relay_addr: None,
        policy,
        database_url: None,
        api_listen: None,
        trust_forwarded_for: false,
        oidc: None,
        public_url: None,
    })
    .await
    .unwrap();
    let addr = server.local_addr().unwrap();
    let pin = server.pin();
    (server, addr, pin)
}

/// Host de test : accepte (ou refuse) chaque offre et renvoie en écho.
async fn spawn_host(addr: SocketAddr, pin: ServerPin, accept: bool) -> DeviceId {
    let identity = Arc::new(DeviceIdentity::generate());
    let id = identity.device_id();
    let mut rv = RendezvousClient::register(addr, pin, &identity)
        .await
        .unwrap();
    tokio::spawn(async move {
        let mut offers: HashMap<Vec<u8>, PublicIdentity> = HashMap::new();
        while let Ok(Some(ev)) = rv.next_event().await {
            match ev {
                Event::Offer(o) => {
                    let who = ident::from_proto(o.requester.as_ref().unwrap()).unwrap();
                    rv.answer(&o, accept).await.unwrap();
                    offers.insert(o.session_id.clone(), who);
                }
                Event::Grant(g) => {
                    let expected = offers.remove(&g.session_id).unwrap();
                    let relay = rv.relay_addr(&g).unwrap();
                    let identity = identity.clone();
                    tokio::spawn(async move {
                        let stream = RelayStream::join(relay, pin, &g).await.unwrap();
                        let mut chan = SecureChannel::respond(stream, &identity).await.unwrap();
                        assert_eq!(chan.remote(), &expected);
                        while let Ok(Some(m)) = chan.recv().await {
                            let mut reply = b"echo:".to_vec();
                            reply.extend_from_slice(&m);
                            if chan.send(&reply).await.is_err() {
                                break;
                            }
                        }
                    });
                }
                Event::Rejected(_) => {}
            }
        }
    });
    id
}

async fn open_session(
    addr: SocketAddr,
    pin: ServerPin,
    target: DeviceId,
) -> Result<(SecureChannel<RelayStream>, RendezvousClient), NetError> {
    let viewer = DeviceIdentity::generate();
    // Ces tests portent sur le relay : pas de connexion directe.
    let options = RegisterOptions {
        accept_direct: false,
        relay_only: true,
    };
    let mut rv = RendezvousClient::register_with(addr, pin, &viewer, options).await?;
    let grant = rv.request_session(target).await?;
    let stream = RelayStream::join(rv.relay_addr(&grant)?, pin, &grant).await?;
    let chan = SecureChannel::initiate(stream, &viewer).await?;
    Ok((chan, rv))
}

#[tokio::test]
async fn encrypted_session_through_relay() {
    let (_server, addr, pin) = start(Policy::private()).await;
    let host = spawn_host(addr, pin, true).await;

    let (mut chan, _rv) = open_session(addr, pin, host).await.unwrap();
    assert_eq!(chan.remote().device_id(), host);

    chan.send(b"bonjour").await.unwrap();
    assert_eq!(chan.recv().await.unwrap().unwrap(), b"echo:bonjour");
    let big = vec![7u8; 60_000];
    chan.send(&big).await.unwrap();
    assert_eq!(chan.recv().await.unwrap().unwrap().len(), 5 + big.len());
}

#[tokio::test]
async fn unknown_target_is_rejected() {
    let (_server, addr, pin) = start(Policy::private()).await;
    let ghost = DeviceIdentity::generate().device_id();
    let err = open_session(addr, pin, ghost).await.err().unwrap();
    assert!(matches!(
        err,
        NetError::Rejected(RejectReason::TargetOffline)
    ));
}

#[tokio::test]
async fn declined_offer_is_rejected() {
    let (_server, addr, pin) = start(Policy::private()).await;
    let host = spawn_host(addr, pin, false).await;
    let err = open_session(addr, pin, host).await.err().unwrap();
    assert!(matches!(err, NetError::Rejected(RejectReason::Declined)));
}

#[tokio::test]
async fn wrong_server_pin_is_refused() {
    let (_server, addr, _pin) = start(Policy::private()).await;
    let wrong = ServerPin::of(b"un autre serveur");
    let id = DeviceIdentity::generate();
    assert!(RendezvousClient::register(addr, wrong, &id).await.is_err());
}

#[tokio::test]
async fn public_mode_caps_concurrent_relay_sessions() {
    let mut policy = public();
    policy.max_relay_sessions = 1;
    policy.max_relay_sessions_per_ip = 0;
    let (_server, addr, pin) = start(policy).await;
    let host = spawn_host(addr, pin, true).await;

    let (mut first, _rv1) = open_session(addr, pin, host).await.unwrap();
    first.send(b"1").await.unwrap();
    assert!(first.recv().await.unwrap().is_some());

    let err = open_session(addr, pin, host).await.err().unwrap();
    assert!(matches!(err, NetError::Rejected(RejectReason::RelayFull)));
}

#[tokio::test]
async fn public_mode_allows_one_relay_session_per_ip() {
    let (_server, addr, pin) = start(public()).await;
    let host = spawn_host(addr, pin, true).await;

    let (first, rv1) = open_session(addr, pin, host).await.unwrap();
    let err = open_session(addr, pin, host).await.err().unwrap();
    assert!(matches!(
        err,
        NetError::Rejected(RejectReason::QuotaExceeded)
    ));

    // La place se libère quand la première session se termine.
    first.close().await.unwrap();
    rv1.close();
    let mut freed = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if open_session(addr, pin, host).await.is_ok() {
            freed = true;
            break;
        }
    }
    assert!(freed, "la place de l'IP n'a pas été libérée");
}

#[tokio::test]
async fn public_mode_cuts_sessions_after_max_duration() {
    let mut policy = public();
    policy.max_relay_seconds = 1;
    let (_server, addr, pin) = start(policy).await;
    let host = spawn_host(addr, pin, true).await;

    let (mut chan, _rv) = open_session(addr, pin, host).await.unwrap();
    chan.send(b"avant").await.unwrap();
    assert!(chan.recv().await.unwrap().is_some());

    // Le relay coupe la session : la lecture se termine (fin ou erreur).
    let ended = tokio::time::timeout(Duration::from_secs(5), chan.recv()).await;
    assert!(matches!(ended, Ok(Ok(None)) | Ok(Err(_))));
}

#[tokio::test]
async fn public_mode_limits_registrations_per_ip() {
    let mut policy = public();
    policy.registrations_per_ip_per_minute = 3;
    let (_server, addr, pin) = start(policy).await;
    let mut clients = Vec::new();
    for _ in 0..3 {
        let id = DeviceIdentity::generate();
        clients.push(RendezvousClient::register(addr, pin, &id).await.unwrap());
    }
    let id = DeviceIdentity::generate();
    let err = RendezvousClient::register(addr, pin, &id)
        .await
        .err()
        .unwrap();
    assert!(
        matches!(err, NetError::Registration(RegisterStatus::RateLimited)),
        "{err:?}"
    );
}

#[tokio::test]
async fn public_mode_limits_connect_requests_per_ip() {
    let mut policy = public();
    policy.connect_requests_per_ip_per_minute = 2;
    let (_server, addr, pin) = start(policy).await;
    let viewer = DeviceIdentity::generate();
    let mut rv = RendezvousClient::register(addr, pin, &viewer)
        .await
        .unwrap();
    // Balayage d'ID : les premiers sont « hors ligne », puis refusés.
    for _ in 0..2 {
        let ghost = DeviceIdentity::generate().device_id();
        let err = rv.request_session(ghost).await.err().unwrap();
        assert!(matches!(
            err,
            NetError::Rejected(RejectReason::TargetOffline)
        ));
    }
    let ghost = DeviceIdentity::generate().device_id();
    let err = rv.request_session(ghost).await.err().unwrap();
    assert!(
        matches!(err, NetError::Rejected(RejectReason::RateLimited)),
        "{err:?}"
    );
}

#[tokio::test]
async fn public_mode_limits_connections_per_ip() {
    let mut policy = public();
    policy.max_connections_per_ip = 2;
    let (_server, addr, pin) = start(policy).await;
    let a = DeviceIdentity::generate();
    let b = DeviceIdentity::generate();
    let ra = RendezvousClient::register(addr, pin, &a).await.unwrap();
    let _rb = RendezvousClient::register(addr, pin, &b).await.unwrap();
    let c = DeviceIdentity::generate();
    assert!(RendezvousClient::register(addr, pin, &c).await.is_err());
    // Une connexion fermée libère sa place.
    ra.close();
    let mut ok = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if RendezvousClient::register(addr, pin, &c).await.is_ok() {
            ok = true;
            break;
        }
    }
    assert!(ok, "la place de la connexion n'a pas été libérée");
}

#[tokio::test]
async fn relay_caps_bitrate_per_direction() {
    let mut policy = public();
    // 800 kbit/s = 100 Ko/s par sens.
    policy.max_relay_bitrate_bps = 800_000;
    let (server, addr, pin) = start(policy).await;
    let host = spawn_host(addr, pin, true).await;
    let (mut chan, _rv) = open_session(addr, pin, host).await.unwrap();

    // 300 Ko aller (et autant en écho) : au moins ~2 s une fois la rafale
    // de 250 ms consommée.
    let started = std::time::Instant::now();
    let chunk = vec![1u8; 30_000];
    for _ in 0..10 {
        chan.send(&chunk).await.unwrap();
        chan.recv().await.unwrap().unwrap();
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(1800),
        "300 Ko passés en {elapsed:?} malgré le plafond"
    );
    assert!(elapsed < Duration::from_secs(10), "trop lent : {elapsed:?}");

    let metrics = server.metrics_text();
    assert!(
        metrics.contains("\ncreamote_relay_sessions_active 1\n"),
        "{metrics}"
    );
    assert!(metrics.contains("\ncreamote_relay_sessions_total 1\n"));
    assert!(!metrics.contains("\ncreamote_relay_bytes_total 0\n"));
}
