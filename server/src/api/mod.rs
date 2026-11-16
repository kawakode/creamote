//! API HTTP de gestion de parc (`/api/v1`).
//!
//! Authentification par jeton porteur (`Authorization: Bearer crm_…`) obtenu
//! via `POST /api/v1/auth/login`. Chaque requête sur une entité est autorisée
//! par le moteur RBAC ; une entité dont l'utilisateur n'est pas membre répond
//! 404, pour ne pas révéler son existence.
//!
//! L'API parle HTTP en clair : en production, placez-la derrière un reverse
//! proxy TLS (Caddy, nginx…), ou laissez-la sur 127.0.0.1.

mod account;
mod book;
mod console;
mod device;
mod entity;
mod keys;
mod sso;

use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use std::net::{IpAddr, SocketAddr};

use axum::extract::ConnectInfo;
use creamote_crypto::DeviceIdentity;

use crate::limiter::{Limits, LoginLimiter};
use serde::Serialize;
use sqlx::Row;

use crate::db::{Db, now};
use crate::rbac::{self, FleetTree, Grant, Permissions, Target};

/// Indique si la machine de clé publique donnée est connectée au rendezvous.
pub type Online = Arc<dyn Fn(&[u8; 32]) -> bool + Send + Sync>;

/// Ce que l'API sait du serveur QUIC qu'elle accompagne.
#[derive(Clone)]
pub struct Services {
    /// Clé qui signe les tickets de session.
    pub ticket_key: Arc<DeviceIdentity>,
    pub online: Online,
    /// Empreinte du certificat du rendezvous, à donner aux hosts.
    pub server_pin: String,
    /// Adresse `hôte:port` annoncée aux pairs, si configurée.
    pub server_address: Option<String>,
    /// Faire confiance à `X-Forwarded-For` (API derrière un reverse proxy) pour
    /// connaître l'adresse du client.
    pub trust_forwarded_for: bool,
    pub login_limits: Limits,
    /// Connexion OpenID Connect, si configurée.
    pub oidc: Option<Arc<crate::oidc::Oidc>>,
    /// Clés de sécurité WebAuthn, si le domaine de la console est connu.
    pub webauthn: Option<Arc<crate::webauthn::WebAuthn>>,
}

impl Services {
    /// Services de test : clé éphémère, aucune machine en ligne.
    pub fn ephemeral() -> Self {
        Self {
            ticket_key: Arc::new(DeviceIdentity::generate()),
            online: Arc::new(|_: &[u8; 32]| false),
            server_pin: String::new(),
            server_address: None,
            trust_forwarded_for: false,
            login_limits: Limits::default(),
            oidc: None,
            webauthn: None,
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    /// Clé qui signe les tickets de session.
    pub ticket_key: Arc<DeviceIdentity>,
    pub online: Online,
    pub server_pin: String,
    pub server_address: Option<String>,
    pub trust_forwarded_for: bool,
    pub limiter: Arc<LoginLimiter>,
    pub oidc: Option<Arc<crate::oidc::Oidc>>,
    pub webauthn: Option<Arc<crate::webauthn::WebAuthn>>,
}

/// API (`/api/v1`) et console web d'administration (`/`).
pub fn router(db: Db, services: Services) -> Router {
    let api = Router::new()
        .route("/auth/login", post(account::login))
        .route("/auth/logout", post(account::logout))
        .route("/auth/methods", get(sso::methods))
        .route("/auth/oidc/start", get(sso::start))
        .route("/auth/oidc/callback", get(sso::callback))
        .route("/auth/oidc/exchange", post(sso::exchange))
        .route("/auth/webauthn/login", post(keys::login))
        .route("/me", get(account::me))
        .route("/me/totp/setup", post(account::totp_setup))
        .route("/me/totp/enable", post(account::totp_enable))
        .route("/me/totp/disable", post(account::totp_disable))
        .route("/me/webauthn", get(keys::list).post(keys::register_finish))
        .route("/me/webauthn/register", post(keys::register_start))
        .route("/me/webauthn/{id}/delete", post(keys::remove))
        .route("/me/address-book", get(book::list).post(book::create))
        .route(
            "/me/address-book/{id}",
            patch(book::update).delete(book::remove),
        )
        .route("/users/{uid}/totp/reset", post(account::totp_reset))
        .route(
            "/users",
            get(account::list_users).post(account::create_user),
        )
        .route("/entities", get(entity::list).post(entity::create))
        .route(
            "/entities/{eid}",
            get(entity::get_one).delete(entity::remove),
        )
        .route(
            "/entities/{eid}/my-permissions",
            get(entity::my_permissions),
        )
        .route(
            "/entities/{eid}/members",
            get(entity::list_members).post(entity::add_member),
        )
        .route(
            "/entities/{eid}/members/{uid}",
            delete(entity::remove_member),
        )
        .route(
            "/entities/{eid}/fleets",
            get(entity::list_fleets).post(entity::create_fleet),
        )
        .route(
            "/entities/{eid}/fleets/{fid}",
            patch(entity::update_fleet).delete(entity::delete_fleet),
        )
        .route(
            "/entities/{eid}/groups",
            get(entity::list_groups).post(entity::create_group),
        )
        .route("/entities/{eid}/groups/{gid}", delete(entity::delete_group))
        .route(
            "/entities/{eid}/groups/{gid}/members",
            get(entity::list_group_members).post(entity::add_group_member),
        )
        .route(
            "/entities/{eid}/groups/{gid}/members/{uid}",
            delete(entity::remove_group_member),
        )
        .route(
            "/entities/{eid}/roles",
            get(entity::list_roles).post(entity::create_role),
        )
        .route("/entities/{eid}/roles/{rid}", delete(entity::delete_role))
        .route(
            "/entities/{eid}/bindings",
            get(entity::list_bindings).post(entity::create_binding),
        )
        .route(
            "/entities/{eid}/bindings/{bid}",
            delete(entity::delete_binding),
        )
        .route("/entities/{eid}/audit", get(entity::audit))
        .route(
            "/entities/{eid}/enrollment-tokens",
            get(device::list_tokens).post(device::create_token),
        )
        .route(
            "/entities/{eid}/enrollment-tokens/{tid}",
            delete(device::delete_token),
        )
        .route("/entities/{eid}/devices", get(device::list))
        .route(
            "/entities/{eid}/devices/{did}",
            get(device::get_one)
                .patch(device::update)
                .delete(device::remove),
        )
        .route("/tickets", post(device::issue_ticket))
        .route("/server-info", get(server_info));
    let state = AppState {
        db,
        ticket_key: services.ticket_key,
        online: services.online,
        server_pin: services.server_pin,
        server_address: services.server_address,
        trust_forwarded_for: services.trust_forwarded_for,
        limiter: Arc::new(LoginLimiter::new(services.login_limits)),
        oidc: services.oidc,
        webauthn: services.webauthn,
    };
    Router::new()
        .nest(
            "/api/v1",
            api.layer(axum::middleware::map_response(api_headers)),
        )
        .merge(console::router())
        .with_state(state)
}

async fn api_headers(mut resp: Response) -> Response {
    let h = resp.headers_mut();
    h.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    h.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    resp
}

/// Informations publiques nécessaires pour enrôler un host.
async fn server_info(
    axum::extract::State(st): axum::extract::State<AppState>,
    _user: CurrentUser,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "server_pin": st.server_pin,
        "server_address": st.server_address,
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// Erreur d'API, rendue en JSON `{ "error": code, "message": texte }`.
#[derive(Debug)]
pub enum ApiError {
    Unauthorized,
    /// Mot de passe correct, second facteur attendu : code TOTP (ou de
    /// secours) et/ou clé de sécurité, avec le défi WebAuthn à signer.
    TotpRequired {
        totp: bool,
        webauthn: Option<serde_json::Value>,
    },
    TotpInvalid,
    /// Trop de tentatives : réessayer après ce nombre de secondes.
    TooManyRequests(u64),
    Forbidden,
    NotFound,
    BadRequest(String),
    Conflict(String),
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            ApiError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "authentification requise".to_owned(),
            ),
            ApiError::TotpRequired { totp, webauthn } => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({
                        "error": "totp_required",
                        "message": "double authentification requise",
                        "totp": totp,
                        "webauthn": webauthn,
                    })),
                )
                    .into_response();
            }
            ApiError::TotpInvalid => (
                StatusCode::UNAUTHORIZED,
                "totp_invalid",
                "code de double authentification invalide".to_owned(),
            ),
            ApiError::TooManyRequests(secs) => {
                let minutes = secs.div_ceil(60).max(1);
                let mut resp = (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(serde_json::json!({
                        "error": "too_many_requests",
                        "message": format!("trop de tentatives, réessayez dans {minutes} min"),
                    })),
                )
                    .into_response();
                resp.headers_mut().insert(
                    axum::http::header::RETRY_AFTER,
                    axum::http::HeaderValue::from(secs.max(1)),
                );
                return resp;
            }
            ApiError::Forbidden => (
                StatusCode::FORBIDDEN,
                "forbidden",
                "permission insuffisante".to_owned(),
            ),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not_found", "introuvable".to_owned()),
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, "bad_request", m),
            ApiError::Conflict(m) => (StatusCode::CONFLICT, "conflict", m),
            ApiError::Internal(m) => {
                tracing::error!("erreur interne de l'API : {m}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    "erreur interne".to_owned(),
                )
            }
        };
        (
            status,
            Json(serde_json::json!({ "error": code, "message": message })),
        )
            .into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        match &e {
            sqlx::Error::Database(d) if d.is_unique_violation() => {
                ApiError::Conflict("existe déjà".to_owned())
            }
            sqlx::Error::RowNotFound => ApiError::NotFound,
            _ => ApiError::Internal(e.to_string()),
        }
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

/// Adresse IP du client : celle de la connexion, ou le premier élément de
/// `X-Forwarded-For` si l'API est configurée derrière un reverse proxy.
pub struct ClientIp(pub Option<IpAddr>);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> ApiResult<Self> {
        if state.trust_forwarded_for {
            let forwarded = parts
                .headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(',').next())
                .and_then(|v| v.trim().parse().ok());
            if forwarded.is_some() {
                return Ok(ClientIp(forwarded));
            }
        }
        Ok(ClientIp(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|c| c.0.ip()),
        ))
    }
}

/// Utilisateur authentifié par son jeton.
#[derive(Debug, Clone, Serialize)]
pub struct CurrentUser {
    pub id: String,
    pub email: String,
    pub display_name: String,
    pub is_superadmin: bool,
    #[serde(skip)]
    token_hash: String,
}

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> ApiResult<Self> {
        let token = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(ApiError::Unauthorized)?;
        let hash = crate::auth::token_hash(token.trim());
        let row = sqlx::query(
            "SELECT u.id, u.email, u.display_name, u.is_superadmin FROM api_sessions s \
             JOIN users u ON u.id = s.user_id \
             WHERE s.token_hash = $1 AND s.expires_at > $2 AND u.disabled = 0",
        )
        .bind(&hash)
        .bind(now())
        .fetch_optional(state.db.pool())
        .await?
        .ok_or(ApiError::Unauthorized)?;
        Ok(CurrentUser {
            id: row.get("id"),
            email: row.get("email"),
            display_name: row.get("display_name"),
            is_superadmin: row.get::<i64, _>("is_superadmin") != 0,
            token_hash: hash,
        })
    }
}

/// Droits d'un utilisateur dans une entité, chargés une fois pour évaluer
/// plusieurs cibles (ex. filtrer une liste de machines).
pub struct Access {
    superadmin: bool,
    grants: Vec<Grant>,
    tree: FleetTree,
}

impl Access {
    pub fn on(&self, target: Target<'_>) -> Permissions {
        if self.superadmin {
            Permissions::ALL
        } else {
            rbac::effective(&self.grants, &self.tree, target)
        }
    }

    pub fn tree(&self) -> &FleetTree {
        &self.tree
    }
}

impl AppState {
    /// Droits de `user` dans l'entité. 404 si l'entité n'existe pas ou si
    /// l'utilisateur n'en est pas membre.
    pub async fn access(&self, user: &CurrentUser, entity_id: &str) -> ApiResult<Access> {
        if user.is_superadmin {
            let exists = sqlx::query("SELECT 1 FROM entities WHERE id = $1")
                .bind(entity_id)
                .fetch_optional(self.db.pool())
                .await?;
            exists.ok_or(ApiError::NotFound)?;
            return Ok(Access {
                superadmin: true,
                grants: Vec::new(),
                tree: self.db.fleet_tree(entity_id).await?,
            });
        }
        if !self.db.is_member(entity_id, &user.id).await? {
            return Err(ApiError::NotFound);
        }
        Ok(Access {
            superadmin: false,
            grants: self.db.grants_for(entity_id, &user.id).await?,
            tree: self.db.fleet_tree(entity_id).await?,
        })
    }

    /// Permissions de `user` sur `target` dans l'entité (404 comme
    /// [`Self::access`]).
    pub async fn permissions(
        &self,
        user: &CurrentUser,
        entity_id: &str,
        target: Target<'_>,
    ) -> ApiResult<Permissions> {
        Ok(self.access(user, entity_id).await?.on(target))
    }

    /// Exige la permission `needed` (403 sinon).
    pub async fn require(
        &self,
        user: &CurrentUser,
        entity_id: &str,
        target: Target<'_>,
        needed: Permissions,
    ) -> ApiResult<()> {
        if self
            .permissions(user, entity_id, target)
            .await?
            .contains(needed)
        {
            Ok(())
        } else {
            Err(ApiError::Forbidden)
        }
    }

    /// Exige d'être membre de l'entité (ou super-admin).
    pub async fn require_member(&self, user: &CurrentUser, entity_id: &str) -> ApiResult<()> {
        self.permissions(user, entity_id, Target::Entity)
            .await
            .map(|_| ())
    }

    pub async fn audit(
        &self,
        entity_id: Option<&str>,
        user: &CurrentUser,
        action: &str,
        target: &str,
        detail: serde_json::Value,
    ) -> ApiResult<()> {
        Ok(self
            .db
            .audit(entity_id, Some(&user.id), action, target, detail)
            .await?)
    }
}

fn require_superadmin(user: &CurrentUser) -> ApiResult<()> {
    if user.is_superadmin {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

fn non_empty(field: &str, value: &str) -> ApiResult<String> {
    let v = value.trim();
    if v.is_empty() || v.len() > 200 {
        Err(ApiError::BadRequest(format!(
            "{field} : 1 à 200 caractères attendus"
        )))
    } else {
        Ok(v.to_owned())
    }
}
