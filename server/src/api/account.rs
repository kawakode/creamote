//! Connexion, profil et comptes utilisateurs.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use sqlx::Row;

use serde_json::json;

use super::{ApiError, ApiResult, AppState, ClientIp, CurrentUser, non_empty, require_superadmin};
use crate::db::{normalize_email, now};
use crate::rbac::Target;
use crate::{auth, totp};

#[derive(Deserialize)]
pub struct LoginRequest {
    email: String,
    password: String,
    /// Code TOTP à 6 chiffres, ou code de secours, si la double
    /// authentification est active.
    #[serde(default)]
    totp_code: Option<String>,
}

#[derive(Serialize)]
pub struct LoginResponse {
    token: String,
    expires_at: i64,
}

/// Compte et secret TOTP, pour la connexion et les opérations sensibles.
struct Credentials {
    id: String,
    password_hash: String,
    totp_secret: Option<String>,
    totp_enabled: bool,
    totp_last_step: i64,
}

async fn credentials(st: &AppState, where_: &str, key: &str) -> ApiResult<Option<Credentials>> {
    let row = sqlx::query(&format!(
        "SELECT id, password_hash, totp_secret, totp_enabled, totp_last_step FROM users \
         WHERE {where_} = $1 AND disabled = 0"
    ))
    .bind(key)
    .fetch_optional(st.db.pool())
    .await?;
    Ok(row.map(|r| Credentials {
        id: r.get("id"),
        password_hash: r.get("password_hash"),
        totp_secret: r.get("totp_secret"),
        totp_enabled: r.get::<i64, _>("totp_enabled") != 0,
        totp_last_step: r.get("totp_last_step"),
    }))
}

/// Vérifie un code TOTP (sans rejeu) ou consomme un code de secours.
async fn check_second_factor(st: &AppState, c: &Credentials, code: &str) -> ApiResult<bool> {
    let Some(secret) = &c.totp_secret else {
        return Ok(false);
    };
    if let Some(step) = totp::verify(secret, code, now(), c.totp_last_step) {
        // Conditionnel : deux requêtes simultanées avec le même code ne
        // passent pas toutes les deux.
        let done = sqlx::query(
            "UPDATE users SET totp_last_step = $1 WHERE id = $2 AND totp_last_step < $3",
        )
        .bind(step)
        .bind(&c.id)
        .bind(step)
        .execute(st.db.pool())
        .await?;
        return Ok(done.rows_affected() == 1);
    }
    let done = sqlx::query(
        "UPDATE recovery_codes SET used_at = $1 WHERE user_id = $2 AND code_hash = $3 AND used_at IS NULL",
    )
    .bind(now())
    .bind(&c.id)
    .bind(auth::token_hash(&totp::normalize_recovery(code)))
    .execute(st.db.pool())
    .await?;
    if done.rows_affected() == 1 {
        st.db
            .audit(
                None,
                Some(&c.id),
                "auth.recovery_code_used",
                &c.id,
                json!({}),
            )
            .await?;
        return Ok(true);
    }
    Ok(false)
}

pub async fn login(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Json<LoginResponse>> {
    let email = normalize_email(&req.email);
    if let Err(wait) = st.limiter.check(&email, ip) {
        return Err(ApiError::TooManyRequests(wait.as_secs()));
    }
    let creds = credentials(&st, "email", &email).await?;
    let hash = creds
        .as_ref()
        .map_or(auth::dummy_hash(), |c| c.password_hash.as_str());
    // Vérification systématique, même pour un e-mail inconnu (temps constant).
    let ok = auth::verify_password(&req.password, hash);
    let fail = |reason: &'static str| {
        let st = st.clone();
        let email = email.clone();
        async move {
            st.limiter.failure(&email, ip);
            st.db
                .audit(
                    None,
                    None,
                    "auth.login_failed",
                    &email,
                    json!({ "reason": reason, "ip": ip.map(|i| i.to_string()) }),
                )
                .await?;
            ApiResult::Ok(())
        }
    };
    let Some(c) = creds.filter(|_| ok) else {
        fail("password").await?;
        return Err(ApiError::Unauthorized);
    };
    if c.totp_enabled {
        match req.totp_code.as_deref().map(str::trim) {
            None | Some("") => return Err(ApiError::TotpRequired),
            Some(code) => {
                if !check_second_factor(&st, &c, code).await? {
                    fail("totp").await?;
                    return Err(ApiError::TotpInvalid);
                }
            }
        }
    }
    st.limiter.success(&email);

    let (token, token_hash) = auth::new_token();
    let expires_at = now() + auth::TOKEN_TTL_SECS;
    sqlx::query(
        "INSERT INTO api_sessions (token_hash, user_id, created_at, expires_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(&token_hash)
    .bind(&c.id)
    .bind(now())
    .bind(expires_at)
    .execute(st.db.pool())
    .await?;
    st.db
        .audit(None, Some(&c.id), "auth.login", &c.id, json!({}))
        .await?;
    Ok(Json(LoginResponse { token, expires_at }))
}

// ------------------------------------------------- double authentification

/// Revérifie le mot de passe de l'utilisateur connecté (opération sensible),
/// avec la même limitation que la connexion.
async fn confirm_password(
    st: &AppState,
    user: &CurrentUser,
    ip: Option<std::net::IpAddr>,
    password: &str,
) -> ApiResult<Credentials> {
    if let Err(wait) = st.limiter.check(&user.email, ip) {
        return Err(ApiError::TooManyRequests(wait.as_secs()));
    }
    let c = credentials(st, "id", &user.id)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    if !auth::verify_password(password, &c.password_hash) {
        st.limiter.failure(&user.email, ip);
        return Err(ApiError::BadRequest("mot de passe incorrect".into()));
    }
    Ok(c)
}

#[derive(Deserialize)]
pub struct PasswordConfirm {
    password: String,
}

/// Prépare la double authentification : nouveau secret, pas encore actif.
pub async fn totp_setup(
    State(st): State<AppState>,
    user: CurrentUser,
    ClientIp(ip): ClientIp,
    Json(req): Json<PasswordConfirm>,
) -> ApiResult<Json<serde_json::Value>> {
    let c = confirm_password(&st, &user, ip, &req.password).await?;
    if c.totp_enabled {
        return Err(ApiError::Conflict(
            "la double authentification est déjà active".into(),
        ));
    }
    let secret = totp::new_secret();
    sqlx::query("UPDATE users SET totp_secret = $1 WHERE id = $2")
        .bind(&secret)
        .bind(&user.id)
        .execute(st.db.pool())
        .await?;
    let uri = totp::otpauth_uri("Creamote", &user.email, &secret);
    Ok(Json(json!({
        "secret": secret,
        "otpauth_uri": uri,
        "qr_svg": totp::qr_svg(&uri),
    })))
}

#[derive(Deserialize)]
pub struct TotpCode {
    code: String,
}

/// Active la double authentification après vérification d'un premier code ;
/// retourne les codes de secours (montrés une seule fois).
pub async fn totp_enable(
    State(st): State<AppState>,
    user: CurrentUser,
    Json(req): Json<TotpCode>,
) -> ApiResult<Json<serde_json::Value>> {
    let c = credentials(&st, "id", &user.id)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    if c.totp_enabled {
        return Err(ApiError::Conflict(
            "la double authentification est déjà active".into(),
        ));
    }
    let Some(secret) = &c.totp_secret else {
        return Err(ApiError::BadRequest("commencez par /me/totp/setup".into()));
    };
    let Some(step) = totp::verify(secret, &req.code, now(), 0) else {
        return Err(ApiError::BadRequest(
            "code invalide : vérifiez l'heure de l'appareil".into(),
        ));
    };
    sqlx::query("UPDATE users SET totp_enabled = 1, totp_last_step = $1 WHERE id = $2")
        .bind(step)
        .bind(&user.id)
        .execute(st.db.pool())
        .await?;
    let codes = replace_recovery_codes(&st, &user.id).await?;
    st.audit(None, &user, "auth.totp_enable", &user.id, json!({}))
        .await?;
    Ok(Json(json!({ "recovery_codes": codes })))
}

async fn replace_recovery_codes(st: &AppState, user_id: &str) -> ApiResult<Vec<String>> {
    sqlx::query("DELETE FROM recovery_codes WHERE user_id = $1")
        .bind(user_id)
        .execute(st.db.pool())
        .await?;
    let codes = totp::new_recovery_codes();
    for code in &codes {
        sqlx::query("INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, $2)")
            .bind(user_id)
            .bind(auth::token_hash(code))
            .execute(st.db.pool())
            .await?;
    }
    Ok(codes)
}

async fn clear_totp(st: &AppState, user_id: &str) -> ApiResult<()> {
    sqlx::query(
        "UPDATE users SET totp_secret = NULL, totp_enabled = 0, totp_last_step = 0 WHERE id = $1",
    )
    .bind(user_id)
    .execute(st.db.pool())
    .await?;
    sqlx::query("DELETE FROM recovery_codes WHERE user_id = $1")
        .bind(user_id)
        .execute(st.db.pool())
        .await?;
    Ok(())
}

#[derive(Deserialize)]
pub struct TotpDisable {
    password: String,
    code: String,
}

pub async fn totp_disable(
    State(st): State<AppState>,
    user: CurrentUser,
    ClientIp(ip): ClientIp,
    Json(req): Json<TotpDisable>,
) -> ApiResult<StatusCode> {
    let c = confirm_password(&st, &user, ip, &req.password).await?;
    if !c.totp_enabled {
        return Err(ApiError::Conflict(
            "la double authentification n'est pas active".into(),
        ));
    }
    if !check_second_factor(&st, &c, &req.code).await? {
        st.limiter.failure(&user.email, ip);
        return Err(ApiError::BadRequest("code invalide".into()));
    }
    clear_totp(&st, &user.id).await?;
    st.audit(None, &user, "auth.totp_disable", &user.id, json!({}))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Super-admin : désactive la double authentification d'un compte (appareil
/// perdu sans codes de secours). Les sessions du compte sont révoquées.
pub async fn totp_reset(
    State(st): State<AppState>,
    user: CurrentUser,
    Path(uid): Path<String>,
) -> ApiResult<StatusCode> {
    require_superadmin(&user)?;
    let exists = sqlx::query("SELECT 1 FROM users WHERE id = $1")
        .bind(&uid)
        .fetch_optional(st.db.pool())
        .await?;
    exists.ok_or(ApiError::NotFound)?;
    clear_totp(&st, &uid).await?;
    sqlx::query("DELETE FROM api_sessions WHERE user_id = $1")
        .bind(&uid)
        .execute(st.db.pool())
        .await?;
    st.audit(None, &user, "auth.totp_reset", &uid, json!({}))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn logout(State(st): State<AppState>, user: CurrentUser) -> ApiResult<StatusCode> {
    sqlx::query("DELETE FROM api_sessions WHERE token_hash = $1")
        .bind(&user.token_hash)
        .execute(st.db.pool())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
pub struct MyEntity {
    id: String,
    name: String,
    permissions: crate::rbac::Permissions,
}

#[derive(Serialize)]
pub struct Me {
    user: CurrentUser,
    entities: Vec<MyEntity>,
    totp_enabled: bool,
    /// Codes de secours encore utilisables.
    recovery_codes_left: i64,
}

pub async fn me(State(st): State<AppState>, user: CurrentUser) -> ApiResult<Json<Me>> {
    let rows = if user.is_superadmin {
        sqlx::query("SELECT id, name FROM entities ORDER BY name")
            .fetch_all(st.db.pool())
            .await?
    } else {
        sqlx::query(
            "SELECT e.id, e.name FROM entities e JOIN memberships m ON m.entity_id = e.id \
             WHERE m.user_id = $1 ORDER BY e.name",
        )
        .bind(&user.id)
        .fetch_all(st.db.pool())
        .await?
    };
    let mut entities = Vec::with_capacity(rows.len());
    for r in rows {
        let id: String = r.get("id");
        let permissions = st.permissions(&user, &id, Target::Entity).await?;
        entities.push(MyEntity {
            name: r.get("name"),
            id,
            permissions,
        });
    }
    let totp_enabled = sqlx::query("SELECT totp_enabled FROM users WHERE id = $1")
        .bind(&user.id)
        .fetch_one(st.db.pool())
        .await?
        .get::<i64, _>("totp_enabled")
        != 0;
    let recovery_codes_left = sqlx::query(
        "SELECT COUNT(*) AS n FROM recovery_codes WHERE user_id = $1 AND used_at IS NULL",
    )
    .bind(&user.id)
    .fetch_one(st.db.pool())
    .await?
    .get::<i64, _>("n");
    Ok(Json(Me {
        user,
        entities,
        totp_enabled,
        recovery_codes_left,
    }))
}

#[derive(Serialize)]
pub struct UserOut {
    id: String,
    email: String,
    display_name: String,
    is_superadmin: bool,
    disabled: bool,
    totp_enabled: bool,
}

pub async fn list_users(
    State(st): State<AppState>,
    user: CurrentUser,
) -> ApiResult<Json<Vec<UserOut>>> {
    require_superadmin(&user)?;
    let rows = sqlx::query(
        "SELECT id, email, display_name, is_superadmin, disabled, totp_enabled FROM users ORDER BY email",
    )
    .fetch_all(st.db.pool())
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| UserOut {
                id: r.get("id"),
                email: r.get("email"),
                display_name: r.get("display_name"),
                is_superadmin: r.get::<i64, _>("is_superadmin") != 0,
                disabled: r.get::<i64, _>("disabled") != 0,
                totp_enabled: r.get::<i64, _>("totp_enabled") != 0,
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
pub struct CreateUser {
    email: String,
    display_name: String,
    password: String,
    #[serde(default)]
    superadmin: bool,
}

pub async fn create_user(
    State(st): State<AppState>,
    user: CurrentUser,
    Json(req): Json<CreateUser>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    require_superadmin(&user)?;
    let email = normalize_email(&req.email);
    if !email.contains('@') {
        return Err(ApiError::BadRequest("e-mail invalide".into()));
    }
    let name = non_empty("display_name", &req.display_name)?;
    check_password(&req.password)?;
    let id = st
        .db
        .create_user(&email, &name, &req.password, req.superadmin)
        .await?;
    st.audit(
        None,
        &user,
        "user.create",
        &id,
        serde_json::json!({ "email": email, "superadmin": req.superadmin }),
    )
    .await?;
    Ok((StatusCode::CREATED, Json(serde_json::json!({ "id": id }))))
}

pub fn check_password(password: &str) -> ApiResult<()> {
    if password.chars().count() < auth::MIN_PASSWORD_LEN {
        return Err(ApiError::BadRequest(format!(
            "mot de passe : {} caractères minimum",
            auth::MIN_PASSWORD_LEN
        )));
    }
    Ok(())
}
