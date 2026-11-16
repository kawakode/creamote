//! Connexion directe entre pairs (M3) : serveur réel en mémoire, host et
//! viewer réels sur la machine locale.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use creamote_crypto::{DeviceId, DeviceIdentity, PublicIdentity};
use creamote_net::ident;
use creamote_net::rendezvous::{Event, RegisterOptions, RendezvousClient};
use creamote_net::secure::SecureChannel;
use creamote_net::stream::{PeerPath, PeerStream};
use creamote_net::tls::ServerPin;
use creamote_net::{NetError, RejectReason};
use creamote_server::{Config, Policy, Server};

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

/// Host de test : accepte chaque offre, établit le flux par le connecteur
/// (direct ou relay) et renvoie en écho, préfixé du chemin emprunté.
async fn spawn_host(addr: SocketAddr, pin: ServerPin, options: RegisterOptions) -> DeviceId {
    let identity = Arc::new(DeviceIdentity::generate());
    let id = identity.device_id();
    let mut rv = RendezvousClient::register_with(addr, pin, &identity, options)
        .await
        .unwrap();
    tokio::spawn(async move {
        let mut offers: HashMap<Vec<u8>, PublicIdentity> = HashMap::new();
        while let Ok(Some(ev)) = rv.next_event().await {
            match ev {
                Event::Offer(o) => {
                    let who = ident::from_proto(o.requester.as_ref().unwrap()).unwrap();
                    rv.answer(&o, true).await.unwrap();
                    offers.insert(o.session_id.clone(), who);
                }
                Event::Grant(g) => {
                    let expected = offers.remove(&g.session_id).unwrap();
                    let connector = rv.connector();
                    let identity = identity.clone();
                    tokio::spawn(async move {
                        let Ok(stream) = connector.host(&g).await else {
                            return;
                        };
                        let tag: &[u8] = match stream.path() {
                            PeerPath::Direct => b"direct:",
                            PeerPath::Relay => b"relay:",
                        };
                        let mut chan = SecureChannel::respond(stream, &identity).await.unwrap();
                        assert_eq!(chan.remote(), &expected);
                        while let Ok(Some(m)) = chan.recv().await {
                            let mut reply = tag.to_vec();
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

const HOST: RegisterOptions = RegisterOptions {
    accept_direct: true,
    relay_only: false,
};
const VIEWER: RegisterOptions = RegisterOptions {
    accept_direct: false,
    relay_only: false,
};
const RELAY_ONLY: RegisterOptions = RegisterOptions {
    accept_direct: false,
    relay_only: true,
};

async fn open_session(
    addr: SocketAddr,
    pin: ServerPin,
    target: DeviceId,
    options: RegisterOptions,
) -> Result<(SecureChannel<PeerStream>, PeerPath, RendezvousClient), NetError> {
    let viewer = DeviceIdentity::generate();
    let mut rv = RendezvousClient::register_with(addr, pin, &viewer, options).await?;
    let grant = rv.request_session(target).await?;
    let stream = rv.connector().viewer(&grant).await?;
    let path = stream.path();
    let chan = SecureChannel::initiate(stream, &viewer).await?;
    assert_eq!(chan.remote().device_id(), target);
    Ok((chan, path, rv))
}

async fn echo(chan: &mut SecureChannel<PeerStream>, msg: &[u8]) -> Vec<u8> {
    chan.send(msg).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), chan.recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn direct_connection_when_both_peers_allow_it() {
    let (_server, addr, pin) = start(Policy::private()).await;
    let host = spawn_host(addr, pin, HOST).await;

    let (mut chan, path, _rv) = open_session(addr, pin, host, VIEWER).await.unwrap();
    assert_eq!(path, PeerPath::Direct);
    assert_eq!(echo(&mut chan, b"bonjour").await, b"direct:bonjour");
    let big = vec![7u8; 60_000];
    assert_eq!(echo(&mut chan, &big).await.len(), 7 + big.len());
}

#[tokio::test]
async fn relay_only_viewer_goes_through_relay() {
    let (_server, addr, pin) = start(Policy::private()).await;
    let host = spawn_host(addr, pin, HOST).await;

    let (mut chan, path, _rv) = open_session(addr, pin, host, RELAY_ONLY).await.unwrap();
    assert_eq!(path, PeerPath::Relay);
    assert_eq!(echo(&mut chan, b"x").await, b"relay:x");
}

#[tokio::test]
async fn relay_only_host_goes_through_relay() {
    let (_server, addr, pin) = start(Policy::private()).await;
    let options = RegisterOptions {
        accept_direct: true,
        relay_only: true,
    };
    let host = spawn_host(addr, pin, options).await;

    let (mut chan, path, _rv) = open_session(addr, pin, host, VIEWER).await.unwrap();
    assert_eq!(path, PeerPath::Relay);
    assert_eq!(echo(&mut chan, b"x").await, b"relay:x");
}

#[tokio::test]
async fn falls_back_to_relay_when_direct_fails() {
    let (_server, addr, pin) = start(Policy::private()).await;
    // Le host n'accepte pas de connexion entrante : le direct échoue.
    let host = spawn_host(addr, pin, VIEWER).await;

    let (mut chan, path, _rv) = open_session(addr, pin, host, VIEWER).await.unwrap();
    assert_eq!(path, PeerPath::Relay);
    assert_eq!(echo(&mut chan, b"repli").await, b"relay:repli");
}

#[tokio::test]
async fn direct_connection_does_not_need_relay_capacity() {
    let mut policy = Policy::public();
    policy.max_relay_sessions = 1;
    policy.max_relay_sessions_per_ip = 0;
    let (_server, addr, pin) = start(policy).await;
    let host = spawn_host(addr, pin, HOST).await;

    // La seule place du relay est occupée.
    let (mut first, path, _rv1) = open_session(addr, pin, host, RELAY_ONLY).await.unwrap();
    assert_eq!(path, PeerPath::Relay);
    assert_eq!(echo(&mut first, b"1").await, b"relay:1");

    // Une autre session aboutit quand même, en direct.
    let (mut second, path, _rv2) = open_session(addr, pin, host, VIEWER).await.unwrap();
    assert_eq!(path, PeerPath::Direct);
    assert_eq!(echo(&mut second, b"2").await, b"direct:2");
}

#[tokio::test]
async fn relay_full_and_direct_impossible_reports_relay_full() {
    let mut policy = Policy::public();
    policy.max_relay_sessions = 1;
    policy.max_relay_sessions_per_ip = 0;
    let (_server, addr, pin) = start(policy).await;
    let host = spawn_host(addr, pin, VIEWER).await;

    let (mut first, _, _rv1) = open_session(addr, pin, host, RELAY_ONLY).await.unwrap();
    assert_eq!(echo(&mut first, b"1").await, b"relay:1");

    let err = open_session(addr, pin, host, VIEWER).await.err().unwrap();
    assert!(
        matches!(err, NetError::Rejected(RejectReason::RelayFull)),
        "{err:?}"
    );
}

#[tokio::test]
async fn two_direct_sessions_to_the_same_host() {
    let (_server, addr, pin) = start(Policy::private()).await;
    let host = spawn_host(addr, pin, HOST).await;

    let ((mut a, pa, _ra), (mut b, pb, _rb)) = tokio::try_join!(
        open_session(addr, pin, host, VIEWER),
        open_session(addr, pin, host, VIEWER)
    )
    .unwrap();
    assert_eq!((pa, pb), (PeerPath::Direct, PeerPath::Direct));
    assert_eq!(echo(&mut a, b"a").await, b"direct:a");
    assert_eq!(echo(&mut b, b"b").await, b"direct:b");
}
