//! Connexion par OpenID Connect (SSO d'entreprise : Entra ID, Google
//! Workspace, Keycloak, Authentik…).
//!
//! Flux « authorization code » avec PKCE (S256), `state` et `nonce` à usage
//! unique. Le jeton d'identité est vérifié avec les clés publiées par le
//! fournisseur (JWKS) : signature (algorithmes asymétriques uniquement),
//! émetteur, audience, expiration, nonce. Le compte Creamote est retrouvé par
//! l'identifiant OIDC déjà lié, sinon par l'e-mail vérifié ; il n'est jamais
//! créé automatiquement.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Durée de vie d'une connexion en cours chez le fournisseur.
const PENDING_TTL: Duration = Duration::from_secs(10 * 60);
/// Durée de vie du code remis à la console après la connexion.
const HANDOFF_TTL: Duration = Duration::from_secs(60);
/// Connexions en cours au plus (le point d'entrée n'est pas authentifié).
const MAX_PENDING: usize = 10_000;
/// Intervalle minimal entre deux rechargements des clés du fournisseur.
const JWKS_REFRESH: Duration = Duration::from_secs(60);
const LEEWAY_SECS: u64 = 60;

#[derive(Debug, Clone)]
pub struct OidcConfig {
    /// URL de l'émetteur, ex. `https://login.example.org/realms/acme`.
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    /// URL publique de la console, ex. `https://admin.example.org` : l'URL de
    /// retour déclarée chez le fournisseur est `<public_url>/api/v1/auth/oidc/callback`.
    pub public_url: String,
    /// Libellé du bouton de connexion.
    pub display_name: String,
    /// Accepter un e-mail que le fournisseur ne déclare pas vérifié
    /// (certains fournisseurs, comme Entra ID, n'envoient pas `email_verified`).
    pub allow_unverified_email: bool,
}

impl OidcConfig {
    pub fn redirect_uri(&self) -> String {
        format!(
            "{}/api/v1/auth/oidc/callback",
            self.public_url.trim_end_matches('/')
        )
    }
}

#[derive(Debug, Clone, Deserialize)]
struct Metadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

struct Pending {
    verifier: String,
    nonce: String,
    created: Instant,
}

/// Identité vérifiée renvoyée par le fournisseur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// `émetteur|sub` : identifiant stable du compte chez le fournisseur.
    pub subject: String,
    pub email: Option<String>,
    pub email_verified: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error("fournisseur injoignable ou réponse invalide : {0}")]
    Provider(String),
    #[error("connexion expirée ou déjà utilisée")]
    UnknownState,
    #[error("le fournisseur a refusé la connexion : {0}")]
    Denied(String),
    #[error("jeton d'identité invalide : {0}")]
    InvalidToken(String),
}

pub struct Oidc {
    config: OidcConfig,
    http: reqwest::Client,
    metadata: tokio::sync::Mutex<Option<Metadata>>,
    jwks: tokio::sync::Mutex<Option<(JwkSet, Instant)>>,
    pending: Mutex<HashMap<String, Pending>>,
    handoffs: Mutex<HashMap<String, (String, Instant)>>,
}

fn random_token() -> String {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    URL_SAFE_NO_PAD.encode(b)
}

/// Algorithmes acceptés pour le jeton d'identité : asymétriques uniquement
/// (jamais `none` ni HMAC, qui utiliserait le secret client).
fn allowed(alg: Algorithm) -> bool {
    matches!(
        alg,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
            | Algorithm::ES256
            | Algorithm::ES384
            | Algorithm::EdDSA
    )
}

#[derive(Deserialize)]
struct Claims {
    sub: String,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<serde_json::Value>,
    #[serde(default)]
    azp: Option<String>,
    #[serde(default)]
    aud: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: Option<String>,
}

impl Oidc {
    pub fn new(config: OidcConfig) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            config,
            http,
            metadata: tokio::sync::Mutex::default(),
            jwks: tokio::sync::Mutex::default(),
            pending: Mutex::default(),
            handoffs: Mutex::default(),
        })
    }

    pub fn config(&self) -> &OidcConfig {
        &self.config
    }

    async fn metadata(&self) -> Result<Metadata, OidcError> {
        let mut cache = self.metadata.lock().await;
        if let Some(m) = cache.as_ref() {
            return Ok(m.clone());
        }
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.config.issuer.trim_end_matches('/')
        );
        let m: Metadata = self
            .http
            .get(&url)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| OidcError::Provider(e.to_string()))?
            .json()
            .await
            .map_err(|e| OidcError::Provider(e.to_string()))?;
        // Le document de découverte doit annoncer l'émetteur configuré.
        if m.issuer.trim_end_matches('/') != self.config.issuer.trim_end_matches('/') {
            return Err(OidcError::Provider(format!(
                "émetteur annoncé « {} » différent de celui configuré",
                m.issuer
            )));
        }
        *cache = Some(m.clone());
        Ok(m)
    }

    /// Clés du fournisseur ; rechargées si `kid` est inconnu (rotation).
    async fn key_for(&self, jwks_uri: &str, kid: Option<&str>) -> Result<DecodingKey, OidcError> {
        let mut cache = self.jwks.lock().await;
        for attempt in 0..2 {
            let stale = cache
                .as_ref()
                .is_none_or(|(_, at)| attempt == 1 && at.elapsed() >= JWKS_REFRESH);
            if stale {
                let set: JwkSet = self
                    .http
                    .get(jwks_uri)
                    .send()
                    .await
                    .and_then(|r| r.error_for_status())
                    .map_err(|e| OidcError::Provider(e.to_string()))?
                    .json()
                    .await
                    .map_err(|e| OidcError::Provider(e.to_string()))?;
                *cache = Some((set, Instant::now()));
            }
            let (set, _) = cache.as_ref().expect("chargé");
            let jwk = match kid {
                Some(k) => set.find(k),
                None if set.keys.len() == 1 => set.keys.first(),
                None => None,
            };
            if let Some(jwk) = jwk {
                return DecodingKey::from_jwk(jwk)
                    .map_err(|e| OidcError::InvalidToken(format!("clé inutilisable : {e}")));
            }
        }
        Err(OidcError::InvalidToken("clé de signature inconnue".into()))
    }

    /// URL de connexion chez le fournisseur.
    pub async fn start(&self) -> Result<String, OidcError> {
        let meta = self.metadata().await?;
        let (state, nonce, verifier) = (random_token(), random_token(), random_token());
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        {
            let mut pending = self.pending.lock().expect("verrou sain");
            pending.retain(|_, p| p.created.elapsed() < PENDING_TTL);
            if pending.len() >= MAX_PENDING {
                return Err(OidcError::Provider(
                    "trop de connexions en cours, réessayez".into(),
                ));
            }
            pending.insert(
                state.clone(),
                Pending {
                    verifier,
                    nonce: nonce.clone(),
                    created: Instant::now(),
                },
            );
        }
        let mut url = reqwest::Url::parse(&meta.authorization_endpoint)
            .map_err(|e| OidcError::Provider(e.to_string()))?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", &self.config.redirect_uri())
            .append_pair("scope", "openid email profile")
            .append_pair("state", &state)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        Ok(url.into())
    }

    /// Termine la connexion : échange le code et vérifie le jeton d'identité.
    pub async fn finish(&self, code: &str, state: &str) -> Result<Identity, OidcError> {
        let pending = self
            .pending
            .lock()
            .expect("verrou sain")
            .remove(state)
            .filter(|p| p.created.elapsed() < PENDING_TTL)
            .ok_or(OidcError::UnknownState)?;
        let meta = self.metadata().await?;

        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("code_verifier", pending.verifier.as_str()),
            ("client_id", self.config.client_id.as_str()),
        ];
        let redirect = self.config.redirect_uri();
        form.push(("redirect_uri", &redirect));
        let mut req = self.http.post(&meta.token_endpoint).form(&form);
        if let Some(secret) = &self.config.client_secret {
            req = req.basic_auth(&self.config.client_id, Some(secret));
        }
        let resp = req
            .send()
            .await
            .map_err(|e| OidcError::Provider(e.to_string()))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(OidcError::Denied(format!(
                "{status} {}",
                body.chars().take(200).collect::<String>()
            )));
        }
        let token: TokenResponse = resp
            .json()
            .await
            .map_err(|e| OidcError::Provider(e.to_string()))?;
        let id_token = token
            .id_token
            .ok_or_else(|| OidcError::InvalidToken("pas de jeton d'identité".into()))?;
        self.verify(&meta, &id_token, &pending.nonce).await
    }

    async fn verify(
        &self,
        meta: &Metadata,
        id_token: &str,
        nonce: &str,
    ) -> Result<Identity, OidcError> {
        let header = jsonwebtoken::decode_header(id_token)
            .map_err(|e| OidcError::InvalidToken(e.to_string()))?;
        if !allowed(header.alg) {
            return Err(OidcError::InvalidToken(format!(
                "algorithme {:?} refusé",
                header.alg
            )));
        }
        let key = self.key_for(&meta.jwks_uri, header.kid.as_deref()).await?;
        let mut v = Validation::new(header.alg);
        v.set_issuer(&[meta.issuer.as_str()]);
        v.set_audience(&[self.config.client_id.as_str()]);
        v.set_required_spec_claims(&["exp", "iat", "iss", "aud", "sub"]);
        v.leeway = LEEWAY_SECS;
        let data = jsonwebtoken::decode::<Claims>(id_token, &key, &v)
            .map_err(|e| OidcError::InvalidToken(e.to_string()))?;
        let c = data.claims;
        if c.nonce.as_deref() != Some(nonce) {
            return Err(OidcError::InvalidToken("nonce invalide".into()));
        }
        // Plusieurs audiences : le jeton doit avoir été émis pour nous (azp).
        let multi_aud = matches!(&c.aud, Some(serde_json::Value::Array(a)) if a.len() > 1);
        if multi_aud && c.azp.as_deref() != Some(self.config.client_id.as_str()) {
            return Err(OidcError::InvalidToken("azp invalide".into()));
        }
        let email_verified = match c.email_verified {
            Some(serde_json::Value::Bool(b)) => b,
            Some(serde_json::Value::String(s)) => s == "true",
            _ => false,
        };
        Ok(Identity {
            subject: format!("{}|{}", meta.issuer, c.sub),
            email: c.email.map(|e| crate::db::normalize_email(&e)),
            email_verified,
        })
    }

    /// Code à usage unique remis à la console (dans le fragment de l'URL),
    /// échangé ensuite contre un jeton d'API.
    pub fn handoff(&self, api_token: String) -> String {
        let code = random_token();
        let mut h = self.handoffs.lock().expect("verrou sain");
        h.retain(|_, (_, at)| at.elapsed() < HANDOFF_TTL);
        h.insert(crate::auth::token_hash(&code), (api_token, Instant::now()));
        code
    }

    pub fn redeem(&self, code: &str) -> Option<String> {
        self.handoffs
            .lock()
            .expect("verrou sain")
            .remove(&crate::auth::token_hash(code))
            .filter(|(_, at)| at.elapsed() < HANDOFF_TTL)
            .map(|(token, _)| token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oidc() -> Oidc {
        Oidc::new(OidcConfig {
            issuer: "https://idp.example.org".into(),
            client_id: "creamote".into(),
            client_secret: None,
            public_url: "https://admin.example.org/".into(),
            display_name: "SSO".into(),
            allow_unverified_email: false,
        })
        .unwrap()
    }

    #[test]
    fn redirect_uri_and_algorithms() {
        assert_eq!(
            oidc().config().redirect_uri(),
            "https://admin.example.org/api/v1/auth/oidc/callback"
        );
        assert!(
            allowed(Algorithm::RS256) && allowed(Algorithm::ES256) && allowed(Algorithm::EdDSA)
        );
        assert!(!allowed(Algorithm::HS256) && !allowed(Algorithm::HS512));
    }

    #[test]
    fn handoff_is_single_use() {
        let o = oidc();
        let code = o.handoff("crm_x".into());
        assert_eq!(o.redeem("autre"), None);
        assert_eq!(o.redeem(&code).as_deref(), Some("crm_x"));
        assert_eq!(o.redeem(&code), None);
    }

    #[tokio::test]
    async fn unknown_state_is_rejected() {
        let err = oidc().finish("code", "état inconnu").await.unwrap_err();
        assert!(matches!(err, OidcError::UnknownState));
    }
}
