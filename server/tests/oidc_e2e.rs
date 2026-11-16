//! Connexion OIDC de bout en bout contre un fournisseur simulé : découverte,
//! autorisation, échange du code avec PKCE, jeton d'identité RS256.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::extract::{Form, Query, State};
use axum::response::{IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use creamote_server::api::{self, Services};
use creamote_server::db::Db;
use creamote_server::oidc::{Oidc, OidcConfig};

const KEY_PEM: &[u8] = include_bytes!("fixtures/oidc-test-idp.pem");
const KEY_N: &str = "7qL08258TXB8uuLqbP-uayPZaQfCKJTGtWoHShEKPoMeS4uxrSBcz70IibBv_thjw5BRISdMStFr5lhWNg9e5ICNmGIvbD_v3d82-eHkQGKCUO4NQqIiWO5hZ9xXs6-1qa2-pVoz_nY_99906ofYILgaT-jyt-DfJV0zOxqkNJu179WlcKeWxKhWmIIzYt3sCMFZRx6vW-BiV_FuVJwGrz9OqBRqdX_d3cp6Hr_MoAZbsuF4xyog3K3UcZjzZsOl6o-Q-Ri65pB7Je26DkyqWwbPWBFwaUSloPzD7ddIWMiglqb2Gn0FdAY-4EYL1G2pERhokboqyzxnfxR8HLzboQ";
const CLIENT_ID: &str = "creamote-console";

/// Ce que le fournisseur simulé met dans le jeton d'identité.
#[derive(Clone)]
struct Behavior {
    sub: String,
    email: Option<String>,
    email_verified: Option<bool>,
    aud: Value,
    alter_nonce: bool,
    sign_with_hs256: bool,
}

impl Behavior {
    fn user(sub: &str, email: &str) -> Self {
        Self {
            sub: sub.into(),
            email: Some(email.into()),
            email_verified: Some(true),
            aud: json!(CLIENT_ID),
            alter_nonce: false,
            sign_with_hs256: false,
        }
    }
}

#[derive(Clone)]
struct Idp {
    issuer: String,
    behavior: Arc<Mutex<Behavior>>,
    /// code -> (nonce, code_challenge)
    codes: Arc<Mutex<HashMap<String, (String, String)>>>,
}

async fn discovery(State(idp): State<Idp>) -> Json<Value> {
    Json(json!({
        "issuer": idp.issuer,
        "authorization_endpoint": format!("{}/authorize", idp.issuer),
        "token_endpoint": format!("{}/token", idp.issuer),
        "jwks_uri": format!("{}/jwks", idp.issuer),
    }))
}

async fn jwks() -> Json<Value> {
    Json(
        json!({ "keys": [{ "kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256", "n": KEY_N, "e": "AQAB" }] }),
    )
}

async fn authorize(State(idp): State<Idp>, Query(q): Query<HashMap<String, String>>) -> Redirect {
    assert_eq!(q["response_type"], "code");
    assert_eq!(q["client_id"], CLIENT_ID);
    assert_eq!(q["code_challenge_method"], "S256");
    let code = format!("code-{}", uuid::Uuid::new_v4());
    idp.codes.lock().unwrap().insert(
        code.clone(),
        (q["nonce"].clone(), q["code_challenge"].clone()),
    );
    Redirect::to(&format!(
        "{}?code={code}&state={}",
        q["redirect_uri"], q["state"]
    ))
}

async fn token(
    State(idp): State<Idp>,
    Form(f): Form<HashMap<String, String>>,
) -> axum::response::Response {
    let Some((nonce, challenge)) = idp.codes.lock().unwrap().remove(&f["code"]) else {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_grant" })),
        )
            .into_response();
    };
    // PKCE : le vérificateur doit correspondre au défi de l'autorisation.
    if URL_SAFE_NO_PAD.encode(Sha256::digest(f["code_verifier"].as_bytes())) != challenge {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_grant" })),
        )
            .into_response();
    }
    let b = idp.behavior.lock().unwrap().clone();
    let now = creamote_server::db::now();
    let mut claims = json!({
        "iss": idp.issuer, "sub": b.sub, "aud": b.aud, "iat": now, "exp": now + 300,
        "nonce": if b.alter_nonce { "autre".to_owned() } else { nonce },
    });
    if let Some(e) = b.email {
        claims["email"] = json!(e);
    }
    if let Some(v) = b.email_verified {
        claims["email_verified"] = json!(v);
    }
    let id_token = if b.sign_with_hs256 {
        // Attaque classique : HMAC avec une valeur publique comme secret.
        let mut h = Header::new(Algorithm::HS256);
        h.kid = Some("k1".into());
        jsonwebtoken::encode(
            &h,
            &claims,
            &EncodingKey::from_secret(KEY_N.as_bytes()).unwrap(),
        )
        .unwrap()
    } else {
        let mut h = Header::new(Algorithm::RS256);
        h.kid = Some("k1".into());
        jsonwebtoken::encode(&h, &claims, &EncodingKey::from_rsa_pem(KEY_PEM).unwrap()).unwrap()
    };
    Json(json!({ "access_token": "x", "token_type": "Bearer", "id_token": id_token }))
        .into_response()
}

struct Env {
    db: Db,
    api: String,
    behavior: Arc<Mutex<Behavior>>,
    http: reqwest::Client,
}

async fn serve(listener: tokio::net::TcpListener, app: Router) {
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap()
    });
}

impl Env {
    async fn start() -> Self {
        let idp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", idp_listener.local_addr().unwrap());
        let behavior = Arc::new(Mutex::new(Behavior::user("s-alice", "alice@example.org")));
        let idp = Idp {
            issuer: issuer.clone(),
            behavior: behavior.clone(),
            codes: Arc::default(),
        };
        let idp_app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/authorize", get(authorize))
            .route("/token", post(token))
            .with_state(idp);
        serve(idp_listener, idp_app).await;

        let api_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api = format!("http://{}", api_listener.local_addr().unwrap());
        let db = Db::connect("sqlite::memory:").await.unwrap();
        let oidc = Oidc::new(OidcConfig {
            issuer,
            client_id: CLIENT_ID.into(),
            client_secret: Some("secret".into()),
            public_url: api.clone(),
            display_name: "Keycloak ACME".into(),
            allow_unverified_email: false,
        })
        .unwrap();
        let services = Services {
            oidc: Some(Arc::new(oidc)),
            ..Services::ephemeral()
        };
        serve(api_listener, api::router(db.clone(), services)).await;
        Self {
            db,
            api,
            behavior,
            http: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
        }
    }

    async fn location(&self, url: &str) -> String {
        let r = self.http.get(url).send().await.unwrap();
        assert!(r.status().is_redirection(), "{url} : {}", r.status());
        r.headers()["location"].to_str().unwrap().to_owned()
    }

    /// Parcours navigateur : console -> fournisseur -> retour. Retourne le
    /// fragment de la console (`oidc/<code>` ou `oidc-error/<raison>`).
    async fn sso(&self) -> String {
        let to_idp = self
            .location(&format!("{}/api/v1/auth/oidc/start", self.api))
            .await;
        let back = self.location(&to_idp).await;
        assert!(back.starts_with(&format!("{}/api/v1/auth/oidc/callback?", self.api)));
        let console = self.location(&back).await;
        console
            .strip_prefix(&format!("{}/#/", self.api))
            .unwrap_or_else(|| panic!("redirection inattendue : {console}"))
            .to_owned()
    }

    async fn exchange(&self, code: &str) -> (u16, Value) {
        let r = self
            .http
            .post(format!("{}/api/v1/auth/oidc/exchange", self.api))
            .json(&json!({ "code": code }))
            .send()
            .await
            .unwrap();
        (r.status().as_u16(), r.json().await.unwrap_or(Value::Null))
    }

    fn set(&self, f: impl FnOnce(&mut Behavior)) {
        f(&mut self.behavior.lock().unwrap());
    }
}

#[tokio::test]
async fn oidc_login_links_existing_account_by_verified_email() {
    let env = Env::start().await;
    let alice = env
        .db
        .create_user(
            "alice@example.org",
            "Alice",
            "mot de passe très long",
            false,
        )
        .await
        .unwrap();

    let methods: Value = env
        .http
        .get(format!("{}/api/v1/auth/methods", env.api))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(methods["oidc"]["name"], json!("Keycloak ACME"));

    let fragment = env.sso().await;
    let code = fragment
        .strip_prefix("oidc/")
        .unwrap_or_else(|| panic!("{fragment}"));
    let (s, login) = env.exchange(code).await;
    assert_eq!(s, 200, "{login}");
    let token = login["token"].as_str().unwrap();
    let me: Value = env
        .http
        .get(format!("{}/api/v1/me", env.api))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me["user"]["id"], json!(alice));
    // Le code de la console ne sert qu'une fois.
    assert_eq!(env.exchange(code).await.0, 401);

    // Lien enregistré : l'e-mail peut changer chez le fournisseur.
    env.set(|b| b.email = Some("alice.martin@example.org".into()));
    assert!(env.sso().await.starts_with("oidc/"));
}

#[tokio::test]
async fn oidc_rejects_unknown_unverified_and_conflicting_identities() {
    let env = Env::start().await;
    env.db
        .create_user(
            "alice@example.org",
            "Alice",
            "mot de passe très long",
            false,
        )
        .await
        .unwrap();

    env.set(|b| *b = Behavior::user("s-x", "inconnu@example.org"));
    assert_eq!(env.sso().await, "oidc-error/no_account");

    env.set(|b| {
        *b = Behavior {
            email_verified: Some(false),
            ..Behavior::user("s-alice", "alice@example.org")
        }
    });
    assert_eq!(env.sso().await, "oidc-error/unverified");
    env.set(|b| {
        *b = Behavior {
            email_verified: None,
            ..Behavior::user("s-alice", "alice@example.org")
        }
    });
    assert_eq!(env.sso().await, "oidc-error/unverified");

    // Premier lien, puis une autre identité avec le même e-mail : refus.
    env.set(|b| *b = Behavior::user("s-alice", "alice@example.org"));
    assert!(env.sso().await.starts_with("oidc/"));
    env.set(|b| *b = Behavior::user("s-imposteur", "alice@example.org"));
    assert_eq!(env.sso().await, "oidc-error/conflict");
}

#[tokio::test]
async fn oidc_rejects_tampered_tokens_and_replayed_state() {
    let env = Env::start().await;
    env.db
        .create_user(
            "alice@example.org",
            "Alice",
            "mot de passe très long",
            false,
        )
        .await
        .unwrap();

    env.set(|b| b.aud = json!("autre-application"));
    assert_eq!(env.sso().await, "oidc-error/token");
    env.set(|b| b.aud = json!([CLIENT_ID, "autre"]));
    assert_eq!(
        env.sso().await,
        "oidc-error/token",
        "plusieurs audiences sans azp"
    );
    env.set(|b| {
        b.aud = json!(CLIENT_ID);
        b.alter_nonce = true;
    });
    assert_eq!(env.sso().await, "oidc-error/token");
    env.set(|b| {
        b.alter_nonce = false;
        b.sign_with_hs256 = true;
    });
    assert_eq!(env.sso().await, "oidc-error/token");
    env.set(|b| b.sign_with_hs256 = false);

    // Rejeu du retour du fournisseur : l'état ne sert qu'une fois.
    let to_idp = env
        .location(&format!("{}/api/v1/auth/oidc/start", env.api))
        .await;
    let back = env.location(&to_idp).await;
    assert!(env.location(&back).await.contains("#/oidc/"));
    assert!(env.location(&back).await.ends_with("#/oidc-error/state"));
    // Retour sans code (refus chez le fournisseur).
    let cancel = format!(
        "{}/api/v1/auth/oidc/callback?error=access_denied&state=x",
        env.api
    );
    assert!(env.location(&cancel).await.ends_with("#/oidc-error/denied"));
}

#[tokio::test]
async fn oidc_disabled_by_default() {
    let db = Db::connect("sqlite::memory:").await.unwrap();
    let app = api::router(db, Services::ephemeral());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    serve(listener, app).await;
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    let m: Value = http
        .get(format!("{base}/api/v1/auth/methods"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(m["oidc"], Value::Null);
    let r = http
        .get(format!("{base}/api/v1/auth/oidc/start"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404);
}
