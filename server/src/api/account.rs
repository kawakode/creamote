//! Connexion, profil et comptes utilisateurs.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use sqlx::Row;

use super::{ApiError, ApiResult, AppState, CurrentUser, non_empty, require_superadmin};
use crate::auth;
use crate::db::{normalize_email, now};
use crate::rbac::Target;

#[derive(Deserialize)]
pub struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    token: String,
    expires_at: i64,
}

pub async fn login(
    State(st): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Json<LoginResponse>> {
    let row = sqlx::query("SELECT id, password_hash FROM users WHERE email = $1 AND disabled = 0")
        .bind(normalize_email(&req.email))
        .fetch_optional(st.db.pool())
        .await?;
    let (user_id, hash) = match &row {
        Some(r) => (
            Some(r.get::<String, _>("id")),
            r.get::<String, _>("password_hash"),
        ),
        None => (None, auth::dummy_hash().to_owned()),
    };
    // Vérification systématique, même pour un e-mail inconnu (temps constant).
    let ok = auth::verify_password(&req.password, &hash);
    let Some(user_id) = user_id.filter(|_| ok) else {
        st.db
            .audit(
                None,
                None,
                "auth.login_failed",
                &normalize_email(&req.email),
                serde_json::json!({}),
            )
            .await?;
        return Err(ApiError::Unauthorized);
    };

    let (token, token_hash) = auth::new_token();
    let expires_at = now() + auth::TOKEN_TTL_SECS;
    sqlx::query(
        "INSERT INTO api_sessions (token_hash, user_id, created_at, expires_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(&token_hash)
    .bind(&user_id)
    .bind(now())
    .bind(expires_at)
    .execute(st.db.pool())
    .await?;
    st.db
        .audit(
            None,
            Some(&user_id),
            "auth.login",
            &user_id,
            serde_json::json!({}),
        )
        .await?;
    Ok(Json(LoginResponse { token, expires_at }))
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
    Ok(Json(Me { user, entities }))
}

#[derive(Serialize)]
pub struct UserOut {
    id: String,
    email: String,
    display_name: String,
    is_superadmin: bool,
    disabled: bool,
}

pub async fn list_users(
    State(st): State<AppState>,
    user: CurrentUser,
) -> ApiResult<Json<Vec<UserOut>>> {
    require_superadmin(&user)?;
    let rows = sqlx::query(
        "SELECT id, email, display_name, is_superadmin, disabled FROM users ORDER BY email",
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
