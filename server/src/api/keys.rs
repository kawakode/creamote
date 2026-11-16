//! Clés de sécurité WebAuthn (voir [`crate::webauthn`]) : enregistrement,
//! liste, suppression, et second facteur à la connexion.
//!
//! Connexion : `POST /auth/login` avec le bon mot de passe répond
//! `totp_required` avec un défi `webauthn` si le compte a des clés ; la console
//! le fait signer par la clé, puis l'envoie à `POST /auth/webauthn/login`.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;

use super::account::{
    LoginResponse, confirm_password, credentials, drop_recovery_codes_if_unused, key_ids,
    open_session, replace_recovery_codes,
};
use super::{ApiError, ApiResult, AppState, ClientIp, CurrentUser, non_empty};
use crate::db::{new_id, now};
use crate::webauthn::{
    AssertionResponse, RegistrationResponse, StoredCredential, UserInfo, WebAuthn, WebAuthnError,
};

/// Nombre maximal de clés par compte.
const MAX_KEYS: usize = 20;

fn service(st: &AppState) -> ApiResult<&WebAuthn> {
    st.webauthn.as_deref().ok_or_else(|| {
        ApiError::Conflict(
            "clés de sécurité indisponibles : configurez l'URL publique de la console (--public-url)"
                .into(),
        )
    })
}

fn rejected(e: WebAuthnError) -> ApiError {
    match e {
        WebAuthnError::Busy => ApiError::TooManyRequests(60),
        WebAuthnError::UnknownChallenge => {
            ApiError::BadRequest("demande expirée, recommencez".into())
        }
        e => ApiError::BadRequest(format!("clé de sécurité refusée : {e}")),
    }
}

#[derive(Serialize)]
pub struct KeyOut {
    id: String,
    name: String,
    created_at: i64,
    last_used_at: Option<i64>,
}

pub async fn list(State(st): State<AppState>, user: CurrentUser) -> ApiResult<Json<Vec<KeyOut>>> {
    let rows = sqlx::query(
        "SELECT id, name, created_at, last_used_at FROM webauthn_credentials \
         WHERE user_id = $1 ORDER BY created_at",
    )
    .bind(&user.id)
    .fetch_all(st.db.pool())
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| KeyOut {
                id: r.get("id"),
                name: r.get("name"),
                created_at: r.get("created_at"),
                last_used_at: r.get("last_used_at"),
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
pub struct PasswordConfirm {
    password: String,
}

/// Début de l'enregistrement d'une clé (mot de passe exigé) : options pour
/// `navigator.credentials.create()`.
pub async fn register_start(
    State(st): State<AppState>,
    user: CurrentUser,
    ClientIp(ip): ClientIp,
    Json(req): Json<PasswordConfirm>,
) -> ApiResult<Json<serde_json::Value>> {
    let w = service(&st)?;
    confirm_password(&st, &user, ip, &req.password).await?;
    let existing = key_ids(&st, &user.id).await?;
    if existing.len() >= MAX_KEYS {
        return Err(ApiError::Conflict(format!(
            "{MAX_KEYS} clés au maximum par compte"
        )));
    }
    let info = UserInfo {
        id: &user.id,
        name: &user.email,
        display_name: &user.display_name,
    };
    Ok(Json(
        w.start_registration(&info, &existing).map_err(rejected)?,
    ))
}

#[derive(Deserialize)]
pub struct RegisterFinish {
    challenge_id: String,
    name: String,
    credential: RegistrationResponse,
}

/// Fin de l'enregistrement. Si c'est le premier second facteur du compte,
/// retourne des codes de secours (montrés une seule fois).
pub async fn register_finish(
    State(st): State<AppState>,
    user: CurrentUser,
    Json(req): Json<RegisterFinish>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let w = service(&st)?;
    let name = non_empty("name", &req.name)?;
    let cred = w
        .finish_registration(&req.challenge_id, &user.id, &req.credential)
        .map_err(rejected)?;
    let c = credentials(&st, "id", &user.id)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let first_factor = !c.totp_enabled && key_ids(&st, &user.id).await?.is_empty();
    let id = new_id();
    sqlx::query(
        "INSERT INTO webauthn_credentials \
         (id, user_id, credential_id, public_key, alg, sign_count, name, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(&id)
    .bind(&user.id)
    .bind(&cred.credential_id)
    .bind(&cred.public_key)
    .bind(cred.alg)
    .bind(i64::from(cred.sign_count))
    .bind(&name)
    .bind(now())
    .execute(st.db.pool())
    .await
    .map_err(|e| match ApiError::from(e) {
        ApiError::Conflict(_) => ApiError::Conflict("cette clé est déjà enregistrée".into()),
        e => e,
    })?;
    let recovery_codes = if first_factor {
        Some(replace_recovery_codes(&st, &user.id).await?)
    } else {
        None
    };
    st.audit(
        None,
        &user,
        "auth.webauthn_add",
        &user.id,
        json!({ "key": id, "name": name, "alg": cred.alg }),
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "id": id, "recovery_codes": recovery_codes })),
    ))
}

/// Supprime une clé (mot de passe exigé). `POST` plutôt que `DELETE` pour
/// porter le mot de passe dans le corps.
pub async fn remove(
    State(st): State<AppState>,
    user: CurrentUser,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
    Json(req): Json<PasswordConfirm>,
) -> ApiResult<StatusCode> {
    confirm_password(&st, &user, ip, &req.password).await?;
    let row = sqlx::query("SELECT name FROM webauthn_credentials WHERE id = $1 AND user_id = $2")
        .bind(&id)
        .bind(&user.id)
        .fetch_optional(st.db.pool())
        .await?
        .ok_or(ApiError::NotFound)?;
    sqlx::query("DELETE FROM webauthn_credentials WHERE id = $1 AND user_id = $2")
        .bind(&id)
        .bind(&user.id)
        .execute(st.db.pool())
        .await?;
    drop_recovery_codes_if_unused(&st, &user.id).await?;
    st.audit(
        None,
        &user,
        "auth.webauthn_remove",
        &user.id,
        json!({ "key": id, "name": row.get::<String, _>("name") }),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct LoginFinish {
    challenge_id: String,
    credential: AssertionResponse,
}

/// Second facteur par clé de sécurité, après le mot de passe.
pub async fn login(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<LoginFinish>,
) -> ApiResult<Json<LoginResponse>> {
    let w = service(&st)?;
    // Défi à usage unique, lié au compte dont le mot de passe a été vérifié.
    let ch = w
        .take_login(&req.challenge_id)
        .map_err(|_| ApiError::BadRequest("demande expirée, reconnectez-vous".into()))?;
    let user = sqlx::query("SELECT email FROM users WHERE id = $1 AND disabled = 0")
        .bind(&ch.user_id)
        .fetch_optional(st.db.pool())
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let email: String = user.get("email");
    if let Err(wait) = st.limiter.check(&email, ip) {
        return Err(ApiError::TooManyRequests(wait.as_secs()));
    }
    let row = sqlx::query(
        "SELECT id, public_key, sign_count FROM webauthn_credentials \
         WHERE credential_id = $1 AND user_id = $2",
    )
    .bind(&req.credential.id)
    .bind(&ch.user_id)
    .fetch_optional(st.db.pool())
    .await?;
    let verified = row.as_ref().map(|r| {
        let stored_count: i64 = r.get("sign_count");
        let public_key: String = r.get("public_key");
        let stored = StoredCredential {
            public_key: &public_key,
            sign_count: u32::try_from(stored_count).unwrap_or(u32::MAX),
        };
        w.verify_assertion(&ch, &stored, &req.credential)
            .map(|count| (r.get::<String, _>("id"), stored_count, count))
    });
    let (key_id, old_count, new_count) = match verified {
        Some(Ok(v)) => v,
        other => {
            let reason = match other {
                Some(Err(e)) => e.to_string(),
                _ => "clé inconnue".to_owned(),
            };
            st.limiter.failure(&email, ip);
            st.db
                .audit(
                    None,
                    Some(&ch.user_id),
                    "auth.login_failed",
                    &email,
                    json!({
                        "reason": "webauthn",
                        "detail": reason,
                        "ip": ip.map(|i| i.to_string()),
                    }),
                )
                .await?;
            return Err(ApiError::TotpInvalid);
        }
    };
    // Conditionnel : deux connexions simultanées avec la même signature ne
    // passent pas toutes les deux.
    let done = sqlx::query(
        "UPDATE webauthn_credentials SET sign_count = $1, last_used_at = $2 \
         WHERE id = $3 AND sign_count = $4",
    )
    .bind(i64::from(new_count))
    .bind(now())
    .bind(&key_id)
    .bind(old_count)
    .execute(st.db.pool())
    .await?;
    if done.rows_affected() != 1 {
        st.limiter.failure(&email, ip);
        return Err(ApiError::TotpInvalid);
    }
    st.limiter.success(&email);
    let (token, expires_at) = open_session(&st, &ch.user_id).await?;
    st.db
        .audit(
            None,
            Some(&ch.user_id),
            "auth.login",
            &ch.user_id,
            json!({ "method": "webauthn", "key": key_id }),
        )
        .await?;
    Ok(Json(LoginResponse { token, expires_at }))
}
