//! Gestion de parc de bout en bout : enrôlement d'un host via le rendezvous,
//! tickets émis par l'API HTTP, vérifiés par le host avant d'accepter.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use creamote_crypto::{DeviceId, DeviceIdentity, PublicIdentity};
use creamote_net::relay::RelayStream;
use creamote_net::rendezvous::{Event, RendezvousClient};
use creamote_net::secure::SecureChannel;
use creamote_net::ticket::{self, Decision, Enrollment};
use creamote_net::tls::ServerPin;
use creamote_net::{EnrollStatus, NetError, RejectReason, ident};
use creamote_server::{Config, Policy, Server};
use serde_json::{Value, json};

const PASSWORD: &str = "mot de passe très long";

struct Env {
    server: Server,
    addr: SocketAddr,
    pin: ServerPin,
    http: reqwest::Client,
    api: String,
}

impl Env {
    async fn start() -> Self {
        let server = Server::start(Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            data_dir: None,
            relay_addr: None,
            policy: Policy::private(),
            database_url: Some("sqlite::memory:".into()),
            api_listen: Some("127.0.0.1:0".parse().unwrap()),
            trust_forwarded_for: false,
            oidc: None,
            public_url: None,
        })
        .await
        .unwrap();
        let api = format!("http://{}/api/v1", server.api_addr().unwrap());
        Self {
            addr: server.local_addr().unwrap(),
            pin: server.pin(),
            server,
            http: reqwest::Client::builder().no_proxy().build().unwrap(),
            api,
        }
    }

    async fn call(&self, path: &str, token: Option<&str>, body: Option<Value>) -> (u16, Value) {
        let url = format!("{}{path}", self.api);
        let mut req = match &body {
            Some(b) => self.http.post(url).json(b),
            None => self.http.get(url),
        };
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        let resp = req.send().await.unwrap();
        let status = resp.status().as_u16();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    async fn user(&self, email: &str, superadmin: bool) -> (String, String) {
        let db = self.server.db().unwrap();
        let id = db
            .create_user(email, email, PASSWORD, superadmin)
            .await
            .unwrap();
        let (s, b) = self
            .call(
                "/auth/login",
                None,
                Some(json!({ "email": email, "password": PASSWORD })),
            )
            .await;
        assert_eq!(s, 200, "{b}");
        (id, b["token"].as_str().unwrap().to_owned())
    }

    async fn ticket(&self, token: &str, host: DeviceId, viewer: &DeviceIdentity) -> (u16, Vec<u8>) {
        let (s, b) = self
            .call(
                "/tickets",
                Some(token),
                Some(json!({ "device_id": host.to_string(), "viewer_key": hex(viewer.public().signing_key()) })),
            )
            .await;
        let t = b["ticket"].as_str().map(unhex).unwrap_or_default();
        (s, t)
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Host géré sans utilisateur présent : n'accepte que les offres que
/// `ticket::decide` valide sans consentement.
fn spawn_managed_host(
    mut rv: RendezvousClient,
    identity: Arc<DeviceIdentity>,
    pin: ServerPin,
    enrollment: Enrollment,
) {
    tokio::spawn(async move {
        let mut offers: HashMap<Vec<u8>, PublicIdentity> = HashMap::new();
        while let Ok(Some(ev)) = rv.next_event().await {
            match ev {
                Event::Offer(o) => {
                    let who = ident::from_proto(o.requester.as_ref().unwrap()).unwrap();
                    let d = ticket::decide(
                        Some(&enrollment),
                        &o.session_ticket,
                        identity.public(),
                        &who,
                        ticket::unix_now(),
                    );
                    let ok = matches!(d, Decision::Accept(_));
                    rv.answer(&o, ok).await.unwrap();
                    if ok {
                        offers.insert(o.session_id.clone(), who);
                    }
                }
                Event::Grant(g) => {
                    let Some(expected) = offers.remove(&g.session_id) else {
                        continue;
                    };
                    let relay = rv.relay_addr(&g).unwrap();
                    let identity = identity.clone();
                    tokio::spawn(async move {
                        let stream = RelayStream::join(relay, pin, &g).await.unwrap();
                        let mut chan = SecureChannel::respond(stream, &identity).await.unwrap();
                        assert_eq!(chan.remote(), &expected);
                        while let Ok(Some(m)) = chan.recv().await {
                            if chan.send(&m).await.is_err() {
                                break;
                            }
                        }
                    });
                }
                Event::Rejected(_) => {}
            }
        }
    });
}

async fn session(
    env: &Env,
    viewer: &DeviceIdentity,
    target: DeviceId,
    ticket: Vec<u8>,
) -> Result<(), NetError> {
    let mut rv = RendezvousClient::register(env.addr, env.pin, viewer).await?;
    let grant = rv.request_session_with_ticket(target, ticket).await?;
    let stream = RelayStream::join(rv.relay_addr(&grant)?, env.pin, &grant).await?;
    let mut chan = SecureChannel::initiate(stream, viewer).await?;
    assert_eq!(chan.remote().device_id(), target);
    chan.send(b"ping").await?;
    assert_eq!(chan.recv().await?.unwrap(), b"ping");
    Ok(())
}

#[tokio::test]
async fn enrolled_host_accepts_only_valid_tickets() {
    let env = Env::start().await;
    let (_, root) = env.user("root@example.org", true).await;
    let (_, alice) = env.user("alice@example.org", false).await;
    let (bob_id, bob) = env.user("bob@example.org", false).await;

    let (s, e) = env
        .call(
            "/entities",
            Some(&root),
            Some(json!({ "name": "ACME", "owner_email": "alice@example.org" })),
        )
        .await;
    assert_eq!(s, 201, "{e}");
    let eid = e["id"].as_str().unwrap().to_owned();
    let path = |p: &str| format!("/entities/{eid}{p}");
    let (_, f) = env
        .call(
            &path("/fleets"),
            Some(&alice),
            Some(json!({ "name": "Compta" })),
        )
        .await;
    let fleet = f["id"].as_str().unwrap().to_owned();
    let (_, t) = env
        .call(
            &path("/enrollment-tokens"),
            Some(&alice),
            Some(json!({ "fleet_id": fleet })),
        )
        .await;
    let token = t["token"].as_str().unwrap().to_owned();

    // Enrôlement du host via le rendezvous.
    let host = Arc::new(DeviceIdentity::generate());
    let host_id = host.device_id();
    let mut rv = RendezvousClient::register(env.addr, env.pin, &host)
        .await
        .unwrap();
    let r = rv.enroll(&token, "PC-Compta-01").await.unwrap();
    assert_eq!(
        (r.entity_name.as_str(), r.fleet_name.as_str()),
        ("ACME", "Compta")
    );
    let err = rv.enroll(&token, "encore").await.unwrap_err();
    assert!(
        matches!(err, NetError::Enrollment(EnrollStatus::InvalidToken)),
        "{err}"
    );
    let enrollment = Enrollment {
        ticket_key: r.ticket_public_key.as_slice().try_into().unwrap(),
        server: env.addr.to_string(),
        server_pin: env.pin.to_string(),
        entity_name: r.entity_name,
        fleet_name: r.fleet_name,
    };
    spawn_managed_host(rv, host.clone(), env.pin, enrollment);

    let (_, devices) = env.call(&path("/devices"), Some(&alice), None).await;
    assert_eq!(devices[0]["name"], json!("PC-Compta-01"));
    assert_eq!(devices[0]["online"], json!(true));
    let did = devices[0]["id"].as_str().unwrap().to_owned();

    // Ticket du propriétaire : session ouverte.
    let viewer = DeviceIdentity::generate();
    let (s, tk) = env.ticket(&alice, host_id, &viewer).await;
    assert_eq!(s, 200);
    session(&env, &viewer, host_id, tk.clone()).await.unwrap();

    // Sans ticket, ou avec le ticket d'un autre appareil : refus.
    let declined =
        |r: Result<(), NetError>| matches!(r, Err(NetError::Rejected(RejectReason::Declined)));
    assert!(declined(session(&env, &viewer, host_id, Vec::new()).await));
    let thief = DeviceIdentity::generate();
    assert!(declined(session(&env, &thief, host_id, tk).await));

    // Technicien (sans `unattended`) : ticket émis, mais refusé par le host
    // en l'absence d'utilisateur pour consentir.
    env.call(
        &path("/members"),
        Some(&alice),
        Some(json!({ "email": "bob@example.org" })),
    )
    .await;
    let (s, b) = env
        .call(
            &path("/bindings"),
            Some(&alice),
            Some(
                json!({ "role_id": "technician", "subject": { "kind": "user", "id": bob_id },
                         "scope": { "kind": "device", "id": did } }),
            ),
        )
        .await;
    assert_eq!(s, 201, "{b}");
    let (s, tk) = env.ticket(&bob, host_id, &viewer).await;
    assert_eq!(s, 200);
    assert!(declined(session(&env, &viewer, host_id, tk).await));
}

#[tokio::test]
async fn enrollment_unavailable_without_fleet_management() {
    let server = Server::start(Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        data_dir: None,
        relay_addr: None,
        policy: Policy::public(),
        database_url: None,
        api_listen: None,
        trust_forwarded_for: false,
        oidc: None,
        public_url: None,
    })
    .await
    .unwrap();
    let host = DeviceIdentity::generate();
    let mut rv = RendezvousClient::register(server.local_addr().unwrap(), server.pin(), &host)
        .await
        .unwrap();
    let err = rv.enroll("cre_x", "pc").await.unwrap_err();
    assert!(matches!(
        err,
        NetError::Enrollment(EnrollStatus::Unavailable)
    ));
}
