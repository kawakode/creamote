//! Clés de sécurité WebAuthn de bout en bout, avec un authentificateur
//! logiciel (ES256, EdDSA, RS256) qui produit les mêmes structures qu'une clé
//! réelle : `clientDataJSON`, données d'authentificateur, attestation CBOR,
//! signatures DER.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ed25519_dalek::Signer;
use jsonwebtoken::{Algorithm, EncodingKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use creamote_server::api::{self, Services};
use creamote_server::db::Db;
use creamote_server::webauthn::{RelyingParty, WebAuthn};

const ORIGIN: &str = "https://admin.example.org";
const RP_ID: &str = "admin.example.org";
const PASSWORD: &str = "mot de passe très long";

const P256_PEM: &[u8] = include_bytes!("fixtures/webauthn-test-p256.pem");
/// Clé publique de la fixture : x || y.
const P256_XY: &str =
    "0F7G6KcMVPb7X0F58qKDm0sRTn_XiVGNumV1qG5PZCgpQivnfDakSUwRc3sBZeNCD_Y4o0fBFl9Cbro2tvMUKQ";
const RSA_PEM: &[u8] = include_bytes!("fixtures/oidc-test-idp.pem");
const RSA_N: &str = "7qL08258TXB8uuLqbP-uayPZaQfCKJTGtWoHShEKPoMeS4uxrSBcz70IibBv_thjw5BRISdMStFr5lhWNg9e5ICNmGIvbD_v3d82-eHkQGKCUO4NQqIiWO5hZ9xXs6-1qa2-pVoz_nY_99906ofYILgaT-jyt-DfJV0zOxqkNJu179WlcKeWxKhWmIIzYt3sCMFZRx6vW-BiV_FuVJwGrz9OqBRqdX_d3cp6Hr_MoAZbsuF4xyog3K3UcZjzZsOl6o-Q-Ri65pB7Je26DkyqWwbPWBFwaUSloPzD7ddIWMiglqb2Gn0FdAY-4EYL1G2pERhokboqyzxnfxR8HLzboQ";

// ------------------------------------------------------------- CBOR (écriture)

fn head(major: u8, n: u64) -> Vec<u8> {
    let m = major << 5;
    match n {
        0..=23 => vec![m | n as u8],
        24..=0xff => vec![m | 24, n as u8],
        0x100..=0xffff => [vec![m | 25], (n as u16).to_be_bytes().to_vec()].concat(),
        _ => [vec![m | 26], (n as u32).to_be_bytes().to_vec()].concat(),
    }
}

fn c_int(i: i64) -> Vec<u8> {
    if i >= 0 {
        head(0, i as u64)
    } else {
        head(1, (-1 - i) as u64)
    }
}

fn c_bytes(b: &[u8]) -> Vec<u8> {
    [head(2, b.len() as u64), b.to_vec()].concat()
}

fn c_text(t: &str) -> Vec<u8> {
    [head(3, t.len() as u64), t.as_bytes().to_vec()].concat()
}

fn c_map(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out = head(5, entries.len() as u64);
    for (k, v) in entries {
        out.extend(k);
        out.extend(v);
    }
    out
}

// ------------------------------------------------- authentificateur logiciel

#[derive(Clone, Copy, Debug)]
enum Kind {
    Es256,
    Ed25519,
    Rs256,
}

#[derive(Clone)]
struct Authenticator {
    kind: Kind,
    cred_id: Vec<u8>,
    counter: u32,
    /// Altérations pour les tests de refus.
    origin: String,
    rp_id: String,
    user_present: bool,
}

/// Signature r || s → DER.
fn raw_to_der(raw: &[u8]) -> Vec<u8> {
    let int = |x: &[u8]| {
        let x = {
            let mut x = x;
            while x.len() > 1 && x[0] == 0 {
                x = &x[1..];
            }
            x
        };
        let mut v = vec![0x02];
        if x[0] & 0x80 != 0 {
            v.push(x.len() as u8 + 1);
            v.push(0);
        } else {
            v.push(x.len() as u8);
        }
        v.extend(x);
        v
    };
    let body = [int(&raw[..32]), int(&raw[32..])].concat();
    [vec![0x30, body.len() as u8], body].concat()
}

impl Authenticator {
    fn new(kind: Kind, id: u8) -> Self {
        Self {
            kind,
            cred_id: [vec![id; 8], uuid::Uuid::new_v4().as_bytes().to_vec()].concat(),
            counter: 0,
            origin: ORIGIN.into(),
            rp_id: RP_ID.into(),
            user_present: true,
        }
    }

    fn ed_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7; 32])
    }

    fn cose_key(&self) -> Vec<u8> {
        match self.kind {
            Kind::Es256 => {
                let xy = B64.decode(P256_XY).unwrap();
                c_map(&[
                    (c_int(1), c_int(2)),
                    (c_int(3), c_int(-7)),
                    (c_int(-1), c_int(1)),
                    (c_int(-2), c_bytes(&xy[..32])),
                    (c_int(-3), c_bytes(&xy[32..])),
                ])
            }
            Kind::Ed25519 => c_map(&[
                (c_int(1), c_int(1)),
                (c_int(3), c_int(-8)),
                (c_int(-1), c_int(6)),
                (
                    c_int(-2),
                    c_bytes(Self::ed_key().verifying_key().as_bytes()),
                ),
            ]),
            Kind::Rs256 => c_map(&[
                (c_int(1), c_int(3)),
                (c_int(3), c_int(-257)),
                (c_int(-1), c_bytes(&B64.decode(RSA_N).unwrap())),
                (c_int(-2), c_bytes(&[1, 0, 1])),
            ]),
        }
    }

    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        match self.kind {
            Kind::Es256 => {
                let key = EncodingKey::from_ec_pem(P256_PEM).unwrap();
                let raw = jsonwebtoken::crypto::sign(msg, &key, Algorithm::ES256).unwrap();
                raw_to_der(&B64.decode(raw).unwrap())
            }
            Kind::Ed25519 => Self::ed_key().sign(msg).to_bytes().to_vec(),
            Kind::Rs256 => {
                let key = EncodingKey::from_rsa_pem(RSA_PEM).unwrap();
                let raw = jsonwebtoken::crypto::sign(msg, &key, Algorithm::RS256).unwrap();
                B64.decode(raw).unwrap()
            }
        }
    }

    fn client_data(&self, kind: &str, challenge: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "type": kind,
            "challenge": challenge,
            "origin": self.origin,
            "crossOrigin": false,
        }))
        .unwrap()
    }

    fn auth_data(&self, flags: u8) -> Vec<u8> {
        let flags = if self.user_present {
            flags | 0x01
        } else {
            flags & !0x01
        };
        let mut d = Sha256::digest(self.rp_id.as_bytes()).to_vec();
        d.push(flags);
        d.extend(self.counter.to_be_bytes());
        d
    }

    /// `navigator.credentials.create()`.
    fn create(&mut self, options: &Value) -> Value {
        let pk = &options["public_key"];
        assert_eq!(pk["rp"]["id"], RP_ID);
        let cd = self.client_data("webauthn.create", pk["challenge"].as_str().unwrap());
        self.counter += 1;
        let mut ad = self.auth_data(0x40);
        ad.extend([0u8; 16]);
        ad.extend((self.cred_id.len() as u16).to_be_bytes());
        ad.extend(&self.cred_id);
        ad.extend(self.cose_key());
        let att = c_map(&[
            (c_text("fmt"), c_text("none")),
            (c_text("attStmt"), c_map(&[])),
            (c_text("authData"), c_bytes(&ad)),
        ]);
        json!({
            "id": B64.encode(&self.cred_id),
            "client_data_json": B64.encode(cd),
            "attestation_object": B64.encode(att),
        })
    }

    /// `navigator.credentials.get()`.
    fn get(&mut self, options: &Value) -> Value {
        let pk = &options["public_key"];
        let cd = self.client_data("webauthn.get", pk["challenge"].as_str().unwrap());
        self.counter += 1;
        let ad = self.auth_data(0);
        let msg = [ad.clone(), Sha256::digest(&cd).to_vec()].concat();
        json!({
            "id": B64.encode(&self.cred_id),
            "client_data_json": B64.encode(cd),
            "authenticator_data": B64.encode(&ad),
            "signature": B64.encode(self.sign(&msg)),
        })
    }
}

// -------------------------------------------------------------- environnement

struct Env {
    db: Db,
    /// Suffixe des e-mails : plusieurs tests peuvent partager une base
    /// PostgreSQL (`CREAMOTE_TEST_DATABASE_URL`).
    tag: String,
    api: String,
    http: reqwest::Client,
}

async fn start(webauthn: bool) -> Env {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = format!("http://{}/api/v1", listener.local_addr().unwrap());
    let url = std::env::var("CREAMOTE_TEST_DATABASE_URL")
        .unwrap_or_else(|_| "sqlite::memory:".to_owned());
    let db = Db::connect(&url).await.unwrap();
    let services = Services {
        webauthn: webauthn
            .then(|| Arc::new(WebAuthn::new(RelyingParty::from_url(ORIGIN).unwrap()))),
        ..Services::ephemeral()
    };
    let app: Router = api::router(db.clone(), services);
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap()
    });
    Env {
        db,
        tag: uuid::Uuid::new_v4().simple().to_string(),
        api,
        http: reqwest::Client::builder().no_proxy().build().unwrap(),
    }
}

impl Env {
    fn mail(&self, email: &str) -> String {
        email.replace('@', &format!("+{}@", self.tag))
    }

    async fn call(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Value,
    ) -> (u16, Value) {
        let mut req = self
            .http
            .request(method.parse().unwrap(), format!("{}{path}", self.api));
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        if method != "GET" {
            req = req.json(&body);
        }
        let r = req.send().await.unwrap();
        (r.status().as_u16(), r.json().await.unwrap_or(Value::Null))
    }

    async fn user(&self, email: &str, superadmin: bool) -> String {
        let email = &self.mail(email);
        self.db
            .create_user(email, email, PASSWORD, superadmin)
            .await
            .unwrap()
    }

    async fn login(&self, email: &str, extra: Value) -> (u16, Value) {
        let mut body = json!({ "email": self.mail(email), "password": PASSWORD });
        if let (Some(b), Some(e)) = (body.as_object_mut(), extra.as_object()) {
            b.extend(e.clone());
        }
        self.call("POST", "/auth/login", None, body).await
    }

    async fn token(&self, email: &str) -> String {
        let (s, r) = self.login(email, json!({})).await;
        assert_eq!(s, 200, "{r}");
        r["token"].as_str().unwrap().to_owned()
    }

    /// Enregistre une clé ; retourne la réponse de l'API.
    async fn register(&self, token: &str, a: &mut Authenticator, name: &str) -> (u16, Value) {
        let (s, opts) = self
            .call(
                "POST",
                "/me/webauthn/register",
                Some(token),
                json!({ "password": PASSWORD }),
            )
            .await;
        assert_eq!(s, 200, "{opts}");
        let cred = a.create(&opts);
        self.call(
            "POST",
            "/me/webauthn",
            Some(token),
            json!({ "challenge_id": opts["challenge_id"], "name": name, "credential": cred }),
        )
        .await
    }

    /// Mot de passe puis clé : retourne (statut, réponse) de la seconde étape.
    async fn login_with_key(&self, email: &str, a: &mut Authenticator) -> (u16, Value) {
        let (s, r) = self.login(email, json!({})).await;
        assert_eq!(s, 401);
        assert_eq!(r["error"], "totp_required");
        let opts = &r["webauthn"];
        assert_eq!(opts["public_key"]["rpId"], RP_ID);
        let cred = a.get(opts);
        self.call(
            "POST",
            "/auth/webauthn/login",
            None,
            json!({ "challenge_id": opts["challenge_id"], "credential": cred }),
        )
        .await
    }
}

#[tokio::test]
async fn security_key_is_a_second_factor() {
    let env = start(true).await;
    env.user("alice@example.org", false).await;
    let token = env.token("alice@example.org").await;

    let (_, methods) = env.call("GET", "/auth/methods", None, json!(null)).await;
    assert_eq!(methods["webauthn"]["rp_id"], RP_ID);

    // Mot de passe exigé pour enregistrer une clé.
    let (s, _) = env
        .call(
            "POST",
            "/me/webauthn/register",
            Some(&token),
            json!({ "password": "faux" }),
        )
        .await;
    assert_eq!(s, 400);

    // Première clé (ES256) : premier second facteur, codes de secours fournis.
    let mut key1 = Authenticator::new(Kind::Es256, 1);
    let (s, r) = env.register(&token, &mut key1, "YubiKey bleue").await;
    assert_eq!(s, 201, "{r}");
    let codes: Vec<String> = serde_json::from_value(r["recovery_codes"].clone()).unwrap();
    assert_eq!(codes.len(), 10);

    // Le mot de passe seul ne suffit plus.
    let (s, r) = env.login("alice@example.org", json!({})).await;
    assert_eq!(
        (s, &r["error"], &r["totp"]),
        (401, &json!("totp_required"), &json!(false))
    );
    assert_eq!(
        r["webauthn"]["public_key"]["allowCredentials"][0]["id"],
        B64.encode(&key1.cred_id)
    );

    // Mot de passe + clé.
    let (s, r) = env.login_with_key("alice@example.org", &mut key1).await;
    assert_eq!(s, 200, "{r}");
    let token = r["token"].as_str().unwrap().to_owned();

    // Rejeu d'une signature : défi à usage unique.
    let (_, r) = env.login("alice@example.org", json!({})).await;
    let opts = r["webauthn"].clone();
    let cred = key1.get(&opts);
    let body = json!({ "challenge_id": opts["challenge_id"], "credential": cred });
    let (s, _) = env
        .call("POST", "/auth/webauthn/login", None, body.clone())
        .await;
    assert_eq!(s, 200);
    let (s, _) = env.call("POST", "/auth/webauthn/login", None, body).await;
    assert_eq!(s, 400, "défi déjà consommé");

    // Clé clonée : compteur en recul.
    let mut clone = key1.clone();
    clone.counter = 1;
    let (s, r) = env.login_with_key("alice@example.org", &mut clone).await;
    assert_eq!((s, &r["error"]), (401, &json!("totp_invalid")));

    // Code de secours en remplacement de la clé.
    let (s, _) = env
        .login("alice@example.org", json!({ "totp_code": codes[0] }))
        .await;
    assert_eq!(s, 200);

    // Deuxième clé (EdDSA) : pas de nouveaux codes ; la première est exclue
    // pour ne pas être enregistrée deux fois.
    let (_, opts) = env
        .call(
            "POST",
            "/me/webauthn/register",
            Some(&token),
            json!({ "password": PASSWORD }),
        )
        .await;
    assert_eq!(
        opts["public_key"]["excludeCredentials"][0]["id"],
        B64.encode(&key1.cred_id)
    );
    let mut key2 = Authenticator::new(Kind::Ed25519, 2);
    let (s, r) = env.register(&token, &mut key2, "Téléphone").await;
    assert_eq!(s, 201, "{r}");
    assert!(r["recovery_codes"].is_null());
    let (s, _) = env.login_with_key("alice@example.org", &mut key2).await;
    assert_eq!(s, 200);

    // La même clé ne s'enregistre pas deux fois.
    let (s, _) = env.register(&token, &mut key2.clone(), "Doublon").await;
    assert_eq!(s, 409);

    let (_, me) = env.call("GET", "/me", Some(&token), json!(null)).await;
    assert_eq!(me["webauthn_keys"], 2);
    assert_eq!(me["recovery_codes_left"], 9);
    let (_, keys) = env
        .call("GET", "/me/webauthn", Some(&token), json!(null))
        .await;
    let keys = keys.as_array().unwrap().clone();
    assert_eq!(keys[0]["name"], "YubiKey bleue");
    assert!(keys[0]["last_used_at"].is_i64());

    // Suppression (mot de passe exigé) ; sans second facteur restant, les
    // codes de secours disparaissent et le mot de passe suffit de nouveau.
    for k in &keys {
        let path = format!("/me/webauthn/{}/delete", k["id"].as_str().unwrap());
        let (s, _) = env
            .call("POST", &path, Some(&token), json!({ "password": "faux" }))
            .await;
        assert_eq!(s, 400);
        let (s, _) = env
            .call("POST", &path, Some(&token), json!({ "password": PASSWORD }))
            .await;
        assert_eq!(s, 204);
    }
    let (_, me) = env.call("GET", "/me", Some(&token), json!(null)).await;
    assert_eq!(
        (
            me["webauthn_keys"].as_i64(),
            me["recovery_codes_left"].as_i64()
        ),
        (Some(0), Some(0))
    );
    env.token("alice@example.org").await;
}

#[tokio::test]
async fn rejects_tampered_or_foreign_responses() {
    let env = start(true).await;
    env.user("alice@example.org", false).await;
    env.user("bob@example.org", false).await;
    let alice = env.token("alice@example.org").await;
    let bob = env.token("bob@example.org").await;

    // Enregistrement refusé : mauvaise origine, mauvais site, utilisateur absent.
    for tamper in [
        |a: &mut Authenticator| a.origin = "https://evil.example".into(),
        |a: &mut Authenticator| a.rp_id = "evil.example".into(),
        |a: &mut Authenticator| a.user_present = false,
    ] {
        let mut a = Authenticator::new(Kind::Rs256, 9);
        tamper(&mut a);
        let (s, r) = env.register(&alice, &mut a, "x").await;
        assert_eq!(s, 400, "{r}");
    }
    // Défi d'enregistrement émis pour un autre compte.
    let (_, opts) = env
        .call(
            "POST",
            "/me/webauthn/register",
            Some(&alice),
            json!({ "password": PASSWORD }),
        )
        .await;
    let cred = Authenticator::new(Kind::Es256, 9).create(&opts);
    let (s, _) = env
        .call(
            "POST",
            "/me/webauthn",
            Some(&bob),
            json!({ "challenge_id": opts["challenge_id"], "name": "x", "credential": cred }),
        )
        .await;
    assert_eq!(s, 400);

    // Clés valides : RS256 pour Alice, EdDSA pour Bob.
    let mut alice_key = Authenticator::new(Kind::Rs256, 1);
    assert_eq!(
        env.register(&alice, &mut alice_key, "Windows Hello")
            .await
            .0,
        201
    );
    let mut bob_key = Authenticator::new(Kind::Ed25519, 2);
    assert_eq!(env.register(&bob, &mut bob_key, "Clé").await.0, 201);

    // La clé de Bob ne sert pas pour le compte d'Alice.
    let (s, _) = env.login_with_key("alice@example.org", &mut bob_key).await;
    assert_eq!(s, 401);

    // Signature altérée.
    let (_, r) = env.login("alice@example.org", json!({})).await;
    let opts = r["webauthn"].clone();
    let mut cred = alice_key.get(&opts);
    let mut sig = B64.decode(cred["signature"].as_str().unwrap()).unwrap();
    sig[10] ^= 1;
    cred["signature"] = json!(B64.encode(sig));
    let (s, _) = env
        .call(
            "POST",
            "/auth/webauthn/login",
            None,
            json!({ "challenge_id": opts["challenge_id"], "credential": cred }),
        )
        .await;
    assert_eq!(s, 401);

    // Origine d'un site tiers (hameçonnage).
    let mut phished = alice_key.clone();
    phished.origin = "https://admin.example.org.evil.example".into();
    assert_eq!(
        env.login_with_key("alice@example.org", &mut phished)
            .await
            .0,
        401
    );

    // Clé valide : connexion.
    let (s, r) = env
        .login_with_key("alice@example.org", &mut alice_key)
        .await;
    assert_eq!(s, 200, "{r}");
}

#[tokio::test]
async fn superadmin_reset_removes_keys_and_disabled_without_public_url() {
    let env = start(true).await;
    env.user("root@example.org", true).await;
    let alice_id = env.user("alice@example.org", false).await;
    let root = env.token("root@example.org").await;
    let alice = env.token("alice@example.org").await;
    let mut key = Authenticator::new(Kind::Es256, 1);
    assert_eq!(env.register(&alice, &mut key, "Clé").await.0, 201);

    let (_, users) = env.call("GET", "/users", Some(&root), json!(null)).await;
    let a = users
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["email"] == env.mail("alice@example.org"))
        .unwrap();
    assert_eq!(a["webauthn_keys"], 1);

    let (s, _) = env
        .call(
            "POST",
            &format!("/users/{alice_id}/totp/reset"),
            Some(&root),
            json!({}),
        )
        .await;
    assert_eq!(s, 204);
    // Sessions révoquées, mot de passe seul de nouveau suffisant.
    let (s, _) = env.call("GET", "/me", Some(&alice), json!(null)).await;
    assert_eq!(s, 401);
    let alice = env.token("alice@example.org").await;
    let (_, me) = env.call("GET", "/me", Some(&alice), json!(null)).await;
    assert_eq!(
        (
            me["webauthn_keys"].as_i64(),
            me["recovery_codes_left"].as_i64()
        ),
        (Some(0), Some(0))
    );

    // Sans URL publique (et hors adresse locale), pas de clés de sécurité.
    let env = start(false).await;
    env.user("alice@example.org", false).await;
    let alice = env.token("alice@example.org").await;
    let (_, methods) = env.call("GET", "/auth/methods", None, json!(null)).await;
    assert!(methods["webauthn"].is_null());
    let (s, _) = env
        .call(
            "POST",
            "/me/webauthn/register",
            Some(&alice),
            json!({ "password": PASSWORD }),
        )
        .await;
    assert_eq!(s, 409);
}
