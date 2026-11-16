//! Machines enrôlées, jetons d'enrôlement et tickets de session.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use creamote_crypto::DeviceId;
use creamote_net::ticket::{self, TICKET_TTL_SECS, TICKET_VERSION};
use creamote_proto::ticket::v1::SessionTicket;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;
use sqlx::any::AnyRow;

use super::{ApiError, ApiResult, AppState, CurrentUser, non_empty};
use crate::auth::{hex, new_enrollment_token};
use crate::db::{new_id, now};
use crate::rbac::{Permissions, Target};

// ------------------------------------------------------- jetons d'enrôlement

#[derive(Deserialize)]
pub struct CreateToken {
    fleet_id: String,
    /// Nombre de machines enrôlables avec ce jeton.
    #[serde(default = "one")]
    uses: i64,
    #[serde(default = "day")]
    ttl_hours: i64,
}

fn one() -> i64 {
    1
}

fn day() -> i64 {
    24
}

pub async fn create_token(
    State(st): State<AppState>,
    user: CurrentUser,
    Path(eid): Path<String>,
    Json(req): Json<CreateToken>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let access = st.access(&user, &eid).await?;
    if !access.tree().contains(&req.fleet_id) {
        return Err(ApiError::BadRequest("parc inconnu".into()));
    }
    if !access
        .on(Target::Fleet(&req.fleet_id))
        .contains(Permissions::MANAGE_DEVICES)
    {
        return Err(ApiError::Forbidden);
    }
    if !(1..=1000).contains(&req.uses) || !(1..=24 * 30).contains(&req.ttl_hours) {
        return Err(ApiError::BadRequest(
            "uses : 1 à 1000 ; ttl_hours : 1 à 720".into(),
        ));
    }
    let (token, hash) = new_enrollment_token();
    let id = new_id();
    let at = now();
    let expires_at = at + req.ttl_hours * 3600;
    sqlx::query(
        "INSERT INTO enrollment_tokens (id, token_hash, entity_id, fleet_id, created_by, created_at, expires_at, uses_left) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(&id)
    .bind(&hash)
    .bind(&eid)
    .bind(&req.fleet_id)
    .bind(&user.id)
    .bind(at)
    .bind(expires_at)
    .bind(req.uses)
    .execute(st.db.pool())
    .await?;
    st.audit(
        Some(&eid),
        &user,
        "enrollment_token.create",
        &id,
        json!({ "fleet_id": req.fleet_id, "uses": req.uses, "expires_at": expires_at }),
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": id,
            "token": token,
            "fleet_id": req.fleet_id,
            "uses_left": req.uses,
            "expires_at": expires_at,
        })),
    ))
}

#[derive(Serialize)]
pub struct TokenOut {
    id: String,
    fleet_id: String,
    created_by: Option<String>,
    created_at: i64,
    expires_at: i64,
    uses_left: i64,
}

/// Jetons encore utilisables des parcs que l'utilisateur gère (la valeur du
/// jeton n'est montrée qu'à la création).
pub async fn list_tokens(
    State(st): State<AppState>,
    user: CurrentUser,
    Path(eid): Path<String>,
) -> ApiResult<Json<Vec<TokenOut>>> {
    let access = st.access(&user, &eid).await?;
    let rows = sqlx::query(
        "SELECT id, fleet_id, created_by, created_at, expires_at, uses_left FROM enrollment_tokens \
         WHERE entity_id = $1 AND expires_at > $2 AND uses_left > 0 ORDER BY created_at",
    )
    .bind(&eid)
    .bind(now())
    .fetch_all(st.db.pool())
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| TokenOut {
                id: r.get("id"),
                fleet_id: r.get("fleet_id"),
                created_by: r.get("created_by"),
                created_at: r.get("created_at"),
                expires_at: r.get("expires_at"),
                uses_left: r.get("uses_left"),
            })
            .filter(|t| {
                access
                    .on(Target::Fleet(&t.fleet_id))
                    .contains(Permissions::MANAGE_DEVICES)
            })
            .collect(),
    ))
}

pub async fn delete_token(
    State(st): State<AppState>,
    user: CurrentUser,
    Path((eid, tid)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let access = st.access(&user, &eid).await?;
    let fleet: String =
        sqlx::query("SELECT fleet_id FROM enrollment_tokens WHERE entity_id = $1 AND id = $2")
            .bind(&eid)
            .bind(&tid)
            .fetch_optional(st.db.pool())
            .await?
            .ok_or(ApiError::NotFound)?
            .get("fleet_id");
    if !access
        .on(Target::Fleet(&fleet))
        .contains(Permissions::MANAGE_DEVICES)
    {
        return Err(ApiError::Forbidden);
    }
    sqlx::query("DELETE FROM enrollment_tokens WHERE id = $1")
        .bind(&tid)
        .execute(st.db.pool())
        .await?;
    st.audit(
        Some(&eid),
        &user,
        "enrollment_token.delete",
        &tid,
        json!({}),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------- machines

#[derive(Serialize)]
pub struct DeviceOut {
    id: String,
    /// ID court affiché, ex. "012 345 678".
    device_id: String,
    name: String,
    platform: String,
    fleet_id: String,
    enrolled_at: i64,
    last_seen: Option<i64>,
    online: bool,
    /// Permissions de l'utilisateur courant sur cette machine.
    permissions: Permissions,
}

const DEVICE_COLUMNS: &str =
    "id, entity_id, device_id, signing_key, name, platform, fleet_id, enrolled_at, last_seen";

struct DeviceRow {
    id: String,
    entity_id: String,
    device_id: String,
    signing_key: [u8; 32],
    name: String,
    platform: String,
    fleet_id: String,
    enrolled_at: i64,
    last_seen: Option<i64>,
}

impl DeviceRow {
    fn from_row(r: &AnyRow) -> ApiResult<Self> {
        let key: String = r.get("signing_key");
        let signing_key = parse_key(&key)
            .ok_or_else(|| ApiError::Internal(format!("clé de machine invalide : {key}")))?;
        Ok(Self {
            id: r.get("id"),
            entity_id: r.get("entity_id"),
            device_id: r.get("device_id"),
            signing_key,
            name: r.get("name"),
            platform: r.get("platform"),
            fleet_id: r.get("fleet_id"),
            enrolled_at: r.get("enrolled_at"),
            last_seen: r.get("last_seen"),
        })
    }

    fn target(&self) -> Target<'_> {
        Target::Device {
            id: &self.id,
            fleet: Some(&self.fleet_id),
        }
    }

    fn out(self, st: &AppState, permissions: Permissions) -> DeviceOut {
        DeviceOut {
            online: (st.online)(&self.signing_key),
            device_id: DeviceId::from_signing_key(&self.signing_key).to_string(),
            id: self.id,
            name: self.name,
            platform: self.platform,
            fleet_id: self.fleet_id,
            enrolled_at: self.enrolled_at,
            last_seen: self.last_seen,
            permissions,
        }
    }
}

fn parse_key(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

async fn load_device(st: &AppState, eid: &str, did: &str) -> ApiResult<DeviceRow> {
    let row = sqlx::query(&format!(
        "SELECT {DEVICE_COLUMNS} FROM devices WHERE entity_id = $1 AND id = $2"
    ))
    .bind(eid)
    .bind(did)
    .fetch_optional(st.db.pool())
    .await?
    .ok_or(ApiError::NotFound)?;
    DeviceRow::from_row(&row)
}

/// Machines sur lesquelles l'utilisateur a au moins une permission.
pub async fn list(
    State(st): State<AppState>,
    user: CurrentUser,
    Path(eid): Path<String>,
) -> ApiResult<Json<Vec<DeviceOut>>> {
    let access = st.access(&user, &eid).await?;
    let rows = sqlx::query(&format!(
        "SELECT {DEVICE_COLUMNS} FROM devices WHERE entity_id = $1 ORDER BY name"
    ))
    .bind(&eid)
    .fetch_all(st.db.pool())
    .await?;
    let mut out = Vec::new();
    for r in &rows {
        let d = DeviceRow::from_row(r)?;
        let p = access.on(d.target());
        if p != Permissions::NONE {
            out.push(d.out(&st, p));
        }
    }
    Ok(Json(out))
}

pub async fn get_one(
    State(st): State<AppState>,
    user: CurrentUser,
    Path((eid, did)): Path<(String, String)>,
) -> ApiResult<Json<DeviceOut>> {
    let access = st.access(&user, &eid).await?;
    let d = load_device(&st, &eid, &did).await?;
    let p = access.on(d.target());
    if p == Permissions::NONE {
        return Err(ApiError::NotFound);
    }
    Ok(Json(d.out(&st, p)))
}

#[derive(Deserialize)]
pub struct UpdateDevice {
    name: Option<String>,
    fleet_id: Option<String>,
}

pub async fn update(
    State(st): State<AppState>,
    user: CurrentUser,
    Path((eid, did)): Path<(String, String)>,
    Json(req): Json<UpdateDevice>,
) -> ApiResult<StatusCode> {
    let access = st.access(&user, &eid).await?;
    let d = load_device(&st, &eid, &did).await?;
    if !access.on(d.target()).contains(Permissions::MANAGE_DEVICES) {
        return Err(ApiError::Forbidden);
    }
    if let Some(name) = &req.name {
        let name = non_empty("name", name)?;
        sqlx::query("UPDATE devices SET name = $1 WHERE id = $2")
            .bind(name)
            .bind(&did)
            .execute(st.db.pool())
            .await?;
    }
    if let Some(fleet) = &req.fleet_id {
        if !access.tree().contains(fleet) {
            return Err(ApiError::BadRequest("parc inconnu".into()));
        }
        // Déplacer une machine exige de gérer aussi le parc de destination.
        if !access
            .on(Target::Fleet(fleet))
            .contains(Permissions::MANAGE_DEVICES)
        {
            return Err(ApiError::Forbidden);
        }
        sqlx::query("UPDATE devices SET fleet_id = $1 WHERE id = $2")
            .bind(fleet)
            .bind(&did)
            .execute(st.db.pool())
            .await?;
    }
    st.audit(
        Some(&eid),
        &user,
        "device.update",
        &did,
        json!({ "name": req.name, "fleet_id": req.fleet_id }),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Retire une machine du parc. Elle ne pourra plus obtenir de ticket ; le
/// host doit être réenrôlé pour revenir.
pub async fn remove(
    State(st): State<AppState>,
    user: CurrentUser,
    Path((eid, did)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let access = st.access(&user, &eid).await?;
    let d = load_device(&st, &eid, &did).await?;
    if !access.on(d.target()).contains(Permissions::MANAGE_DEVICES) {
        return Err(ApiError::Forbidden);
    }
    sqlx::query(
        "DELETE FROM role_bindings WHERE entity_id = $1 AND scope_kind = 'device' AND scope_id = $2",
    )
    .bind(&eid)
    .bind(&did)
    .execute(st.db.pool())
    .await?;
    sqlx::query("DELETE FROM devices WHERE id = $1")
        .bind(&did)
        .execute(st.db.pool())
        .await?;
    st.audit(
        Some(&eid),
        &user,
        "device.delete",
        &did,
        json!({ "device_id": d.device_id, "name": d.name }),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// La machine `did` appartient-elle à l'entité ? (portée des attributions)
pub async fn device_in_entity(st: &AppState, eid: &str, did: &str) -> ApiResult<bool> {
    Ok(
        sqlx::query("SELECT 1 FROM devices WHERE entity_id = $1 AND id = $2")
            .bind(eid)
            .bind(did)
            .fetch_optional(st.db.pool())
            .await?
            .is_some(),
    )
}

/// Parc d'une machine de l'entité, pour évaluer les permissions sur elle.
pub async fn device_fleet(st: &AppState, eid: &str, did: &str) -> ApiResult<String> {
    Ok(load_device(st, eid, did).await?.fleet_id)
}

// ---------------------------------------------------------------- tickets

#[derive(Deserialize)]
pub struct TicketRequest {
    /// ID court de la machine ("012 345 678" ou "012345678").
    device_id: String,
    /// Clé publique Ed25519 (hex) de l'appareil qui ouvrira la session.
    viewer_key: String,
}

/// Émet un ticket de session signé : le host enrôlé ne l'accepte que de
/// l'appareil `viewer_key`, avant expiration.
pub async fn issue_ticket(
    State(st): State<AppState>,
    user: CurrentUser,
    Json(req): Json<TicketRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let id = DeviceId::parse(&req.device_id)
        .ok_or_else(|| ApiError::BadRequest("device_id invalide".into()))?;
    let viewer = parse_key(&req.viewer_key)
        .ok_or_else(|| ApiError::BadRequest("viewer_key : 32 octets en hexadécimal".into()))?;
    let rows = sqlx::query(&format!(
        "SELECT {DEVICE_COLUMNS} FROM devices WHERE device_id = $1"
    ))
    .bind(format!("{:09}", id.as_u32()))
    .fetch_all(st.db.pool())
    .await?;
    // L'ID court est dérivé de la clé : en cas (improbable) de collision, on
    // retient la machine sur laquelle l'utilisateur a des droits.
    let mut found = None;
    for r in &rows {
        let d = DeviceRow::from_row(r)?;
        let Ok(access) = st.access(&user, &d.entity_id).await else {
            continue;
        };
        let p = access.on(d.target());
        if p != Permissions::NONE {
            found = Some((d, p));
            break;
        }
    }
    let (d, perms) = found.ok_or(ApiError::NotFound)?;
    if !perms.contains(Permissions::VIEW) {
        return Err(ApiError::Forbidden);
    }
    let issued_at = now();
    let expires_at = issued_at + TICKET_TTL_SECS;
    let t = SessionTicket {
        version: TICKET_VERSION,
        host_signing_key: d.signing_key.to_vec(),
        viewer_signing_key: viewer.to_vec(),
        user_id: user.id.clone(),
        user_email: user.email.clone(),
        permissions: perms.bits(),
        issued_at,
        expires_at,
        entity_id: d.entity_id.clone(),
    };
    let signed = ticket::sign(&st.ticket_key, &t);
    st.audit(
        Some(&d.entity_id),
        &user,
        "ticket.issue",
        &d.id,
        json!({ "viewer_key": hex(&viewer), "permissions": perms }),
    )
    .await?;
    Ok(Json(json!({
        "ticket": hex(&signed),
        "device_id": DeviceId::from_signing_key(&d.signing_key).to_string(),
        "permissions": perms,
        "expires_at": expires_at,
    })))
}
