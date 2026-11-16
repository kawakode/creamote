//! Connexion par OpenID Connect (voir [`crate::oidc`]).
//!
//! 1. `GET /auth/oidc/start` redirige vers le fournisseur ;
//! 2. le fournisseur revient sur `GET /auth/oidc/callback` ;
//! 3. le serveur ouvre une session et redirige vers la console avec un code à
//!    usage unique dans le fragment (`/#/oidc/<code>`), jamais envoyé aux
//!    serveurs intermédiaires ;
//! 4. la console échange ce code contre le jeton d'API
//!    (`POST /auth/oidc/exchange`).
//!
//! La double authentification locale (TOTP) n'est pas demandée : elle relève
//! du fournisseur d'identité.

use axum::Json;
use axum::extract::{Query, State};
use axum::response::Redirect;
use serde::Deserialize;
use serde_json::json;
use sqlx::Row;

use super::account::{LoginResponse, open_session};
use super::{ApiError, ApiResult, AppState};
use crate::oidc::{Identity, OidcError};

/// Méthodes de connexion proposées (sans authentification).
pub async fn methods(State(st): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({
        "password": true,
        "oidc": st.oidc.as_ref().map(|o| json!({ "name": o.config().display_name })),
    }))
}

fn console(st: &AppState, fragment: &str) -> Redirect {
    let base = st
        .oidc
        .as_ref()
        .map(|o| o.config().public_url.trim_end_matches('/').to_owned())
        .unwrap_or_default();
    Redirect::to(&format!("{base}/#/{fragment}"))
}

pub async fn start(State(st): State<AppState>) -> ApiResult<Redirect> {
    let oidc = st.oidc.as_ref().ok_or(ApiError::NotFound)?;
    match oidc.start().await {
        Ok(url) => Ok(Redirect::to(&url)),
        Err(e) => {
            tracing::warn!("OIDC : {e}");
            Ok(console(&st, "oidc-error/provider"))
        }
    }
}

#[derive(Deserialize)]
pub struct Callback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

pub async fn callback(
    State(st): State<AppState>,
    Query(q): Query<Callback>,
) -> ApiResult<Redirect> {
    let oidc = st.oidc.clone().ok_or(ApiError::NotFound)?;
    let (Some(code), Some(state)) = (q.code, q.state.clone()) else {
        tracing::info!(error = ?q.error, "OIDC : connexion annulée par le fournisseur");
        if let Some(state) = q.state.as_deref() {
            // Consomme l'état pour qu'il ne puisse pas resservir.
            let _ = oidc.finish("", state).await;
        }
        return Ok(console(&st, "oidc-error/denied"));
    };
    let identity = match oidc.finish(&code, &state).await {
        Ok(i) => i,
        Err(e) => {
            tracing::warn!("OIDC : {e}");
            let reason = match e {
                OidcError::UnknownState => "state",
                OidcError::Denied(_) => "denied",
                OidcError::Provider(_) => "provider",
                OidcError::InvalidToken(_) => "token",
            };
            audit_failure(&st, None, reason).await;
            return Ok(console(&st, &format!("oidc-error/{reason}")));
        }
    };
    match link_account(&st, &identity).await? {
        Ok(user_id) => {
            let (token, _) = open_session(&st, &user_id).await?;
            st.db
                .audit(
                    None,
                    Some(&user_id),
                    "auth.login",
                    &user_id,
                    json!({ "method": "oidc" }),
                )
                .await?;
            Ok(console(&st, &format!("oidc/{}", oidc.handoff(token))))
        }
        Err(reason) => {
            audit_failure(&st, identity.email.as_deref(), reason).await;
            Ok(console(&st, &format!("oidc-error/{reason}")))
        }
    }
}

async fn audit_failure(st: &AppState, email: Option<&str>, reason: &str) {
    let r = st
        .db
        .audit(
            None,
            None,
            "auth.login_failed",
            email.unwrap_or("oidc"),
            json!({ "method": "oidc", "reason": reason }),
        )
        .await;
    if let Err(e) = r {
        tracing::warn!("audit impossible : {e}");
    }
}

/// Compte Creamote de cette identité : déjà lié, sinon même e-mail vérifié
/// (le lien est alors enregistré). `Err(raison)` sinon.
async fn link_account(st: &AppState, id: &Identity) -> ApiResult<Result<String, &'static str>> {
    let linked = sqlx::query("SELECT id, disabled FROM users WHERE oidc_subject = $1")
        .bind(&id.subject)
        .fetch_optional(st.db.pool())
        .await?;
    if let Some(r) = linked {
        return Ok(if r.get::<i64, _>("disabled") != 0 {
            Err("disabled")
        } else {
            Ok(r.get("id"))
        });
    }
    let Some(email) = &id.email else {
        return Ok(Err("no_account"));
    };
    let allow_unverified = st
        .oidc
        .as_ref()
        .is_some_and(|o| o.config().allow_unverified_email);
    if !id.email_verified && !allow_unverified {
        return Ok(Err("unverified"));
    }
    let Some(r) = sqlx::query("SELECT id, disabled, oidc_subject FROM users WHERE email = $1")
        .bind(email)
        .fetch_optional(st.db.pool())
        .await?
    else {
        return Ok(Err("no_account"));
    };
    if r.get::<i64, _>("disabled") != 0 {
        return Ok(Err("disabled"));
    }
    // Déjà lié à une autre identité : on ne réattribue pas le compte sur la
    // seule foi de l'e-mail.
    if r.get::<Option<String>, _>("oidc_subject").is_some() {
        return Ok(Err("conflict"));
    }
    let user_id: String = r.get("id");
    sqlx::query("UPDATE users SET oidc_subject = $1 WHERE id = $2 AND oidc_subject IS NULL")
        .bind(&id.subject)
        .bind(&user_id)
        .execute(st.db.pool())
        .await?;
    st.db
        .audit(
            None,
            Some(&user_id),
            "auth.oidc_link",
            &user_id,
            json!({ "subject": id.subject }),
        )
        .await?;
    Ok(Ok(user_id))
}

#[derive(Deserialize)]
pub struct Exchange {
    code: String,
}

pub async fn exchange(
    State(st): State<AppState>,
    Json(req): Json<Exchange>,
) -> ApiResult<Json<LoginResponse>> {
    let oidc = st.oidc.as_ref().ok_or(ApiError::NotFound)?;
    let token = oidc.redeem(&req.code).ok_or(ApiError::Unauthorized)?;
    let expires_at = sqlx::query("SELECT expires_at FROM api_sessions WHERE token_hash = $1")
        .bind(crate::auth::token_hash(&token))
        .fetch_optional(st.db.pool())
        .await?
        .ok_or(ApiError::Unauthorized)?
        .get("expires_at");
    Ok(Json(LoginResponse { token, expires_at }))
}
