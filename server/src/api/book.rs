//! Carnet d'adresses personnel : machines non gérées (hors parc) que
//! l'utilisateur joint régulièrement par leur ID. Les machines des parcs
//! sont listées par l'API des entités.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use creamote_crypto::DeviceId;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;

use super::{ApiError, ApiResult, AppState, CurrentUser, non_empty};
use crate::db::{new_id, now};

/// Nombre maximal d'entrées par utilisateur.
const MAX_ENTRIES: i64 = 1000;
const MAX_NOTES: usize = 2000;

#[derive(Serialize)]
pub struct EntryOut {
    id: String,
    label: String,
    /// ID affiché, ex. "012 345 678".
    device_id: String,
    notes: String,
    created_at: i64,
}

fn parse_id(s: &str) -> ApiResult<String> {
    DeviceId::parse(s)
        .map(|id| format!("{:09}", id.as_u32()))
        .ok_or_else(|| ApiError::BadRequest("device_id : 9 chiffres attendus".into()))
}

fn display_id(stored: &str) -> String {
    DeviceId::parse(stored).map_or_else(|| stored.to_owned(), |id| id.to_string())
}

fn notes(s: Option<&str>) -> ApiResult<String> {
    let n = s.unwrap_or_default().trim();
    if n.chars().count() > MAX_NOTES {
        return Err(ApiError::BadRequest(format!(
            "notes : {MAX_NOTES} caractères maximum"
        )));
    }
    Ok(n.to_owned())
}

pub async fn list(State(st): State<AppState>, user: CurrentUser) -> ApiResult<Json<Vec<EntryOut>>> {
    let rows = sqlx::query(
        "SELECT id, label, device_id, notes, created_at FROM address_book \
         WHERE user_id = $1 ORDER BY label",
    )
    .bind(&user.id)
    .fetch_all(st.db.pool())
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| EntryOut {
                id: r.get("id"),
                label: r.get("label"),
                device_id: display_id(&r.get::<String, _>("device_id")),
                notes: r.get("notes"),
                created_at: r.get("created_at"),
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
pub struct CreateEntry {
    label: String,
    device_id: String,
    notes: Option<String>,
}

pub async fn create(
    State(st): State<AppState>,
    user: CurrentUser,
    Json(req): Json<CreateEntry>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let label = non_empty("label", &req.label)?;
    let device_id = parse_id(&req.device_id)?;
    let notes = notes(req.notes.as_deref())?;
    let count: i64 = sqlx::query("SELECT COUNT(*) AS n FROM address_book WHERE user_id = $1")
        .bind(&user.id)
        .fetch_one(st.db.pool())
        .await?
        .get("n");
    if count >= MAX_ENTRIES {
        return Err(ApiError::Conflict(format!(
            "carnet plein ({MAX_ENTRIES} entrées)"
        )));
    }
    let id = new_id();
    sqlx::query(
        "INSERT INTO address_book (id, user_id, label, device_id, notes, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&id)
    .bind(&user.id)
    .bind(label)
    .bind(device_id)
    .bind(notes)
    .bind(now())
    .execute(st.db.pool())
    .await?;
    Ok((StatusCode::CREATED, Json(json!({ "id": id }))))
}

#[derive(Deserialize)]
pub struct UpdateEntry {
    label: Option<String>,
    device_id: Option<String>,
    notes: Option<String>,
}

pub async fn update(
    State(st): State<AppState>,
    user: CurrentUser,
    Path(id): Path<String>,
    Json(req): Json<UpdateEntry>,
) -> ApiResult<StatusCode> {
    let row = sqlx::query(
        "SELECT label, device_id, notes FROM address_book WHERE id = $1 AND user_id = $2",
    )
    .bind(&id)
    .bind(&user.id)
    .fetch_optional(st.db.pool())
    .await?
    .ok_or(ApiError::NotFound)?;
    let label = match &req.label {
        Some(l) => non_empty("label", l)?,
        None => row.get("label"),
    };
    let device_id = match &req.device_id {
        Some(d) => parse_id(d)?,
        None => row.get("device_id"),
    };
    let notes = match &req.notes {
        Some(n) => notes(Some(n))?,
        None => row.get("notes"),
    };
    sqlx::query(
        "UPDATE address_book SET label = $1, device_id = $2, notes = $3 WHERE id = $4 AND user_id = $5",
    )
    .bind(label)
    .bind(device_id)
    .bind(notes)
    .bind(&id)
    .bind(&user.id)
    .execute(st.db.pool())
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn remove(
    State(st): State<AppState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let done = sqlx::query("DELETE FROM address_book WHERE id = $1 AND user_id = $2")
        .bind(&id)
        .bind(&user.id)
        .execute(st.db.pool())
        .await?;
    if done.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}
