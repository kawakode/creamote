//! Entités et tout ce qu'elles contiennent : membres, parcs, groupes de
//! sécurité, rôles, attributions et journal d'audit.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::json;
use sqlx::Row;

use super::{ApiError, ApiResult, AppState, CurrentUser, non_empty, require_superadmin};
use crate::db::{new_id, normalize_email, now};
use crate::rbac::{BUILTIN_ROLES, Permissions, Scope, Target};

type Created = (StatusCode, Json<serde_json::Value>);

fn created(id: &str) -> Created {
    (StatusCode::CREATED, Json(json!({ "id": id })))
}

// ---------------------------------------------------------------- entités

#[derive(Serialize)]
pub struct EntityOut {
    id: String,
    name: String,
    created_at: i64,
}

pub async fn list(
    State(st): State<AppState>,
    user: CurrentUser,
) -> ApiResult<Json<Vec<EntityOut>>> {
    let rows = if user.is_superadmin {
        sqlx::query("SELECT id, name, created_at FROM entities ORDER BY name")
            .fetch_all(st.db.pool())
            .await?
    } else {
        sqlx::query(
            "SELECT e.id, e.name, e.created_at FROM entities e \
             JOIN memberships m ON m.entity_id = e.id WHERE m.user_id = $1 ORDER BY e.name",
        )
        .bind(&user.id)
        .fetch_all(st.db.pool())
        .await?
    };
    Ok(Json(
        rows.into_iter()
            .map(|r| EntityOut {
                id: r.get("id"),
                name: r.get("name"),
                created_at: r.get("created_at"),
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
pub struct CreateEntity {
    name: String,
    /// Utilisateur existant qui devient propriétaire de l'entité.
    owner_email: Option<String>,
}

pub async fn create(
    State(st): State<AppState>,
    user: CurrentUser,
    Json(req): Json<CreateEntity>,
) -> ApiResult<Created> {
    require_superadmin(&user)?;
    let name = non_empty("name", &req.name)?;
    let owner = match &req.owner_email {
        Some(email) => Some(user_id_by_email(&st, email).await?),
        None => None,
    };
    let id = new_id();
    sqlx::query("INSERT INTO entities (id, name, created_at) VALUES ($1, $2, $3)")
        .bind(&id)
        .bind(&name)
        .bind(now())
        .execute(st.db.pool())
        .await?;
    if let Some(owner) = &owner {
        insert_member(&st, &id, owner).await?;
        insert_binding(&st, &id, "owner", "user", owner, &Scope::Entity).await?;
    }
    st.audit(
        Some(&id),
        &user,
        "entity.create",
        &id,
        json!({ "name": name, "owner": owner }),
    )
    .await?;
    Ok(created(&id))
}

pub async fn get_one(
    State(st): State<AppState>,
    user: CurrentUser,
    Path(eid): Path<String>,
) -> ApiResult<Json<EntityOut>> {
    st.require_member(&user, &eid).await?;
    let r = sqlx::query("SELECT id, name, created_at FROM entities WHERE id = $1")
        .bind(&eid)
        .fetch_one(st.db.pool())
        .await?;
    Ok(Json(EntityOut {
        id: r.get("id"),
        name: r.get("name"),
        created_at: r.get("created_at"),
    }))
}

pub async fn remove(
    State(st): State<AppState>,
    user: CurrentUser,
    Path(eid): Path<String>,
) -> ApiResult<StatusCode> {
    require_superadmin(&user)?;
    // Les parcs se référencent entre eux : on les détache avant la cascade.
    sqlx::query("UPDATE fleets SET parent_id = NULL WHERE entity_id = $1")
        .bind(&eid)
        .execute(st.db.pool())
        .await?;
    let done = sqlx::query("DELETE FROM entities WHERE id = $1")
        .bind(&eid)
        .execute(st.db.pool())
        .await?;
    if done.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    st.audit(Some(&eid), &user, "entity.delete", &eid, json!({}))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct PermissionsQuery {
    fleet_id: Option<String>,
}

pub async fn my_permissions(
    State(st): State<AppState>,
    user: CurrentUser,
    Path(eid): Path<String>,
    Query(q): Query<PermissionsQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let target = match q.fleet_id.as_deref() {
        Some(f) => Target::Fleet(f),
        None => Target::Entity,
    };
    let p = st.permissions(&user, &eid, target).await?;
    Ok(Json(json!({ "permissions": p })))
}

// ---------------------------------------------------------------- membres

#[derive(Serialize)]
pub struct MemberOut {
    user_id: String,
    email: String,
    display_name: String,
}

pub async fn list_members(
    State(st): State<AppState>,
    user: CurrentUser,
    Path(eid): Path<String>,
) -> ApiResult<Json<Vec<MemberOut>>> {
    st.require_member(&user, &eid).await?;
    let rows = sqlx::query(
        "SELECT u.id, u.email, u.display_name FROM memberships m JOIN users u ON u.id = m.user_id \
         WHERE m.entity_id = $1 ORDER BY u.email",
    )
    .bind(&eid)
    .fetch_all(st.db.pool())
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| MemberOut {
                user_id: r.get("id"),
                email: r.get("email"),
                display_name: r.get("display_name"),
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
pub struct AddMember {
    email: String,
}

pub async fn add_member(
    State(st): State<AppState>,
    user: CurrentUser,
    Path(eid): Path<String>,
    Json(req): Json<AddMember>,
) -> ApiResult<Created> {
    st.require(&user, &eid, Target::Entity, Permissions::MANAGE_ACCESS)
        .await?;
    let uid = user_id_by_email(&st, &req.email).await?;
    insert_member(&st, &eid, &uid).await?;
    st.audit(
        Some(&eid),
        &user,
        "member.add",
        &uid,
        json!({ "email": normalize_email(&req.email) }),
    )
    .await?;
    Ok(created(&uid))
}

pub async fn remove_member(
    State(st): State<AppState>,
    user: CurrentUser,
    Path((eid, uid)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    st.require(&user, &eid, Target::Entity, Permissions::MANAGE_ACCESS)
        .await?;
    if !st.db.is_member(&eid, &uid).await? {
        return Err(ApiError::NotFound);
    }
    ensure_admin_remains(&st, &eid, Removal::User(&uid)).await?;
    let pool = st.db.pool();
    sqlx::query(
        "DELETE FROM group_members WHERE user_id = $1 AND group_id IN \
         (SELECT id FROM security_groups WHERE entity_id = $2)",
    )
    .bind(&uid)
    .bind(&eid)
    .execute(pool)
    .await?;
    sqlx::query(
        "DELETE FROM role_bindings WHERE entity_id = $1 AND subject_kind = 'user' AND subject_id = $2",
    )
    .bind(&eid)
    .bind(&uid)
    .execute(pool)
    .await?;
    sqlx::query("DELETE FROM memberships WHERE entity_id = $1 AND user_id = $2")
        .bind(&eid)
        .bind(&uid)
        .execute(pool)
        .await?;
    st.audit(Some(&eid), &user, "member.remove", &uid, json!({}))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------- parcs

#[derive(Serialize)]
pub struct FleetOut {
    id: String,
    name: String,
    parent_id: Option<String>,
}

pub async fn list_fleets(
    State(st): State<AppState>,
    user: CurrentUser,
    Path(eid): Path<String>,
) -> ApiResult<Json<Vec<FleetOut>>> {
    st.require_member(&user, &eid).await?;
    let rows =
        sqlx::query("SELECT id, name, parent_id FROM fleets WHERE entity_id = $1 ORDER BY name")
            .bind(&eid)
            .fetch_all(st.db.pool())
            .await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| FleetOut {
                id: r.get("id"),
                name: r.get("name"),
                parent_id: r.get("parent_id"),
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
pub struct CreateFleet {
    name: String,
    parent_id: Option<String>,
}

/// Cible RBAC pour créer ou rattacher un parc sous `parent`.
fn parent_target(parent: Option<&str>) -> Target<'_> {
    parent.map_or(Target::Entity, Target::Fleet)
}

pub async fn create_fleet(
    State(st): State<AppState>,
    user: CurrentUser,
    Path(eid): Path<String>,
    Json(req): Json<CreateFleet>,
) -> ApiResult<Created> {
    let name = non_empty("name", &req.name)?;
    let parent = req.parent_id.as_deref();
    st.require(
        &user,
        &eid,
        parent_target(parent),
        Permissions::MANAGE_DEVICES,
    )
    .await?;
    if let Some(p) = parent
        && !st.db.fleet_tree(&eid).await?.contains(p)
    {
        return Err(ApiError::BadRequest("parc parent inconnu".into()));
    }
    let id = new_id();
    sqlx::query("INSERT INTO fleets (id, entity_id, parent_id, name, created_at) VALUES ($1, $2, $3, $4, $5)")
        .bind(&id)
        .bind(&eid)
        .bind(parent)
        .bind(&name)
        .bind(now())
        .execute(st.db.pool())
        .await?;
    st.audit(
        Some(&eid),
        &user,
        "fleet.create",
        &id,
        json!({ "name": name, "parent_id": parent }),
    )
    .await?;
    Ok(created(&id))
}

/// Distingue un champ absent (`None`) d'un champ à `null` (`Some(None)`).
fn double_option<'de, D, T>(d: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d).map(Some)
}

#[derive(Deserialize)]
pub struct UpdateFleet {
    name: Option<String>,
    /// Absent : inchangé ; `null` : à la racine ; id : sous ce parc.
    #[serde(default, deserialize_with = "double_option")]
    parent_id: Option<Option<String>>,
}

pub async fn update_fleet(
    State(st): State<AppState>,
    user: CurrentUser,
    Path((eid, fid)): Path<(String, String)>,
    Json(req): Json<UpdateFleet>,
) -> ApiResult<StatusCode> {
    st.require(
        &user,
        &eid,
        Target::Fleet(&fid),
        Permissions::MANAGE_DEVICES,
    )
    .await?;
    let tree = st.db.fleet_tree(&eid).await?;
    if !tree.contains(&fid) {
        return Err(ApiError::NotFound);
    }
    if let Some(name) = &req.name {
        let name = non_empty("name", name)?;
        sqlx::query("UPDATE fleets SET name = $1 WHERE id = $2")
            .bind(&name)
            .bind(&fid)
            .execute(st.db.pool())
            .await?;
    }
    if let Some(new_parent) = &req.parent_id {
        let new_parent = new_parent.as_deref();
        if let Some(p) = new_parent {
            if !tree.contains(p) {
                return Err(ApiError::BadRequest("parc parent inconnu".into()));
            }
            if tree.is_ancestor_or_self(&fid, p) {
                return Err(ApiError::Conflict(
                    "un parc ne peut pas être déplacé sous lui-même".into(),
                ));
            }
        }
        st.require(
            &user,
            &eid,
            parent_target(new_parent),
            Permissions::MANAGE_DEVICES,
        )
        .await?;
        sqlx::query("UPDATE fleets SET parent_id = $1 WHERE id = $2")
            .bind(new_parent)
            .bind(&fid)
            .execute(st.db.pool())
            .await?;
    }
    st.audit(
        Some(&eid),
        &user,
        "fleet.update",
        &fid,
        json!({ "name": req.name, "parent_id": req.parent_id }),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_fleet(
    State(st): State<AppState>,
    user: CurrentUser,
    Path((eid, fid)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    st.require(
        &user,
        &eid,
        Target::Fleet(&fid),
        Permissions::MANAGE_DEVICES,
    )
    .await?;
    if !st.db.fleet_tree(&eid).await?.contains(&fid) {
        return Err(ApiError::NotFound);
    }
    let child = sqlx::query("SELECT 1 FROM fleets WHERE parent_id = $1")
        .bind(&fid)
        .fetch_optional(st.db.pool())
        .await?;
    if child.is_some() {
        return Err(ApiError::Conflict("le parc contient des sous-parcs".into()));
    }
    sqlx::query(
        "DELETE FROM role_bindings WHERE entity_id = $1 AND scope_kind = 'fleet' AND scope_id = $2",
    )
    .bind(&eid)
    .bind(&fid)
    .execute(st.db.pool())
    .await?;
    sqlx::query("DELETE FROM fleets WHERE id = $1")
        .bind(&fid)
        .execute(st.db.pool())
        .await?;
    st.audit(Some(&eid), &user, "fleet.delete", &fid, json!({}))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------- groupes

#[derive(Serialize)]
pub struct GroupOut {
    id: String,
    name: String,
}

pub async fn list_groups(
    State(st): State<AppState>,
    user: CurrentUser,
    Path(eid): Path<String>,
) -> ApiResult<Json<Vec<GroupOut>>> {
    st.require_member(&user, &eid).await?;
    let rows =
        sqlx::query("SELECT id, name FROM security_groups WHERE entity_id = $1 ORDER BY name")
            .bind(&eid)
            .fetch_all(st.db.pool())
            .await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| GroupOut {
                id: r.get("id"),
                name: r.get("name"),
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
pub struct CreateGroup {
    name: String,
}

pub async fn create_group(
    State(st): State<AppState>,
    user: CurrentUser,
    Path(eid): Path<String>,
    Json(req): Json<CreateGroup>,
) -> ApiResult<Created> {
    st.require(&user, &eid, Target::Entity, Permissions::MANAGE_ACCESS)
        .await?;
    let name = non_empty("name", &req.name)?;
    let id = new_id();
    sqlx::query(
        "INSERT INTO security_groups (id, entity_id, name, created_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(&id)
    .bind(&eid)
    .bind(&name)
    .bind(now())
    .execute(st.db.pool())
    .await?;
    st.audit(
        Some(&eid),
        &user,
        "group.create",
        &id,
        json!({ "name": name }),
    )
    .await?;
    Ok(created(&id))
}

async fn group_in_entity(st: &AppState, eid: &str, gid: &str) -> ApiResult<()> {
    sqlx::query("SELECT 1 FROM security_groups WHERE id = $1 AND entity_id = $2")
        .bind(gid)
        .bind(eid)
        .fetch_optional(st.db.pool())
        .await?
        .map(|_| ())
        .ok_or(ApiError::NotFound)
}

pub async fn delete_group(
    State(st): State<AppState>,
    user: CurrentUser,
    Path((eid, gid)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    st.require(&user, &eid, Target::Entity, Permissions::MANAGE_ACCESS)
        .await?;
    group_in_entity(&st, &eid, &gid).await?;
    ensure_admin_remains(&st, &eid, Removal::Group(&gid)).await?;
    sqlx::query("DELETE FROM role_bindings WHERE entity_id = $1 AND subject_kind = 'group' AND subject_id = $2")
        .bind(&eid)
        .bind(&gid)
        .execute(st.db.pool())
        .await?;
    sqlx::query("DELETE FROM group_members WHERE group_id = $1")
        .bind(&gid)
        .execute(st.db.pool())
        .await?;
    sqlx::query("DELETE FROM security_groups WHERE id = $1")
        .bind(&gid)
        .execute(st.db.pool())
        .await?;
    st.audit(Some(&eid), &user, "group.delete", &gid, json!({}))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_group_members(
    State(st): State<AppState>,
    user: CurrentUser,
    Path((eid, gid)): Path<(String, String)>,
) -> ApiResult<Json<Vec<MemberOut>>> {
    st.require_member(&user, &eid).await?;
    group_in_entity(&st, &eid, &gid).await?;
    let rows = sqlx::query(
        "SELECT u.id, u.email, u.display_name FROM group_members g JOIN users u ON u.id = g.user_id \
         WHERE g.group_id = $1 ORDER BY u.email",
    )
    .bind(&gid)
    .fetch_all(st.db.pool())
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| MemberOut {
                user_id: r.get("id"),
                email: r.get("email"),
                display_name: r.get("display_name"),
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
pub struct AddGroupMember {
    user_id: String,
}

pub async fn add_group_member(
    State(st): State<AppState>,
    user: CurrentUser,
    Path((eid, gid)): Path<(String, String)>,
    Json(req): Json<AddGroupMember>,
) -> ApiResult<Created> {
    st.require(&user, &eid, Target::Entity, Permissions::MANAGE_ACCESS)
        .await?;
    group_in_entity(&st, &eid, &gid).await?;
    if !st.db.is_member(&eid, &req.user_id).await? {
        return Err(ApiError::BadRequest(
            "l'utilisateur doit d'abord être membre de l'entité".into(),
        ));
    }
    sqlx::query("INSERT INTO group_members (group_id, user_id) VALUES ($1, $2)")
        .bind(&gid)
        .bind(&req.user_id)
        .execute(st.db.pool())
        .await?;
    st.audit(
        Some(&eid),
        &user,
        "group.member_add",
        &gid,
        json!({ "user_id": req.user_id }),
    )
    .await?;
    Ok(created(&req.user_id))
}

pub async fn remove_group_member(
    State(st): State<AppState>,
    user: CurrentUser,
    Path((eid, gid, uid)): Path<(String, String, String)>,
) -> ApiResult<StatusCode> {
    st.require(&user, &eid, Target::Entity, Permissions::MANAGE_ACCESS)
        .await?;
    group_in_entity(&st, &eid, &gid).await?;
    ensure_admin_remains(&st, &eid, Removal::GroupMember(&gid, &uid)).await?;
    let done = sqlx::query("DELETE FROM group_members WHERE group_id = $1 AND user_id = $2")
        .bind(&gid)
        .bind(&uid)
        .execute(st.db.pool())
        .await?;
    if done.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    st.audit(
        Some(&eid),
        &user,
        "group.member_remove",
        &gid,
        json!({ "user_id": uid }),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------- rôles

#[derive(Serialize)]
pub struct RoleOut {
    id: String,
    name: String,
    permissions: Permissions,
    builtin: bool,
}

pub async fn list_roles(
    State(st): State<AppState>,
    user: CurrentUser,
    Path(eid): Path<String>,
) -> ApiResult<Json<Vec<RoleOut>>> {
    st.require_member(&user, &eid).await?;
    let mut roles: Vec<RoleOut> = BUILTIN_ROLES
        .iter()
        .map(|r| RoleOut {
            id: r.id.into(),
            name: r.name.into(),
            permissions: r.permissions,
            builtin: true,
        })
        .collect();
    let rows =
        sqlx::query("SELECT id, name, permissions FROM roles WHERE entity_id = $1 ORDER BY name")
            .bind(&eid)
            .fetch_all(st.db.pool())
            .await?;
    roles.extend(rows.into_iter().map(|r| RoleOut {
        id: r.get("id"),
        name: r.get("name"),
        permissions: Permissions::from_bits_truncate(r.get::<i64, _>("permissions") as u64),
        builtin: false,
    }));
    Ok(Json(roles))
}

#[derive(Deserialize)]
pub struct CreateRole {
    name: String,
    permissions: Permissions,
}

pub async fn create_role(
    State(st): State<AppState>,
    user: CurrentUser,
    Path(eid): Path<String>,
    Json(req): Json<CreateRole>,
) -> ApiResult<Created> {
    st.require(&user, &eid, Target::Entity, Permissions::MANAGE_ACCESS)
        .await?;
    let name = non_empty("name", &req.name)?;
    let id = new_id();
    sqlx::query("INSERT INTO roles (id, entity_id, name, permissions, created_at) VALUES ($1, $2, $3, $4, $5)")
        .bind(&id)
        .bind(&eid)
        .bind(&name)
        .bind(req.permissions.bits() as i64)
        .bind(now())
        .execute(st.db.pool())
        .await?;
    st.audit(
        Some(&eid),
        &user,
        "role.create",
        &id,
        json!({ "name": name, "permissions": req.permissions }),
    )
    .await?;
    Ok(created(&id))
}

pub async fn delete_role(
    State(st): State<AppState>,
    user: CurrentUser,
    Path((eid, rid)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    st.require(&user, &eid, Target::Entity, Permissions::MANAGE_ACCESS)
        .await?;
    let used = sqlx::query("SELECT 1 FROM role_bindings WHERE entity_id = $1 AND role_id = $2")
        .bind(&eid)
        .bind(&rid)
        .fetch_optional(st.db.pool())
        .await?;
    if used.is_some() {
        return Err(ApiError::Conflict("rôle encore attribué".into()));
    }
    let done = sqlx::query("DELETE FROM roles WHERE entity_id = $1 AND id = $2")
        .bind(&eid)
        .bind(&rid)
        .execute(st.db.pool())
        .await?;
    if done.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    st.audit(Some(&eid), &user, "role.delete", &rid, json!({}))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------- attributions

#[derive(Serialize, Deserialize)]
pub struct Ref {
    kind: String,
    #[serde(default)]
    id: String,
}

#[derive(Serialize)]
pub struct BindingOut {
    id: String,
    role_id: String,
    subject: Ref,
    scope: Ref,
}

pub async fn list_bindings(
    State(st): State<AppState>,
    user: CurrentUser,
    Path(eid): Path<String>,
) -> ApiResult<Json<Vec<BindingOut>>> {
    st.require_member(&user, &eid).await?;
    let rows = sqlx::query(
        "SELECT id, role_id, subject_kind, subject_id, scope_kind, scope_id FROM role_bindings \
         WHERE entity_id = $1 ORDER BY created_at",
    )
    .bind(&eid)
    .fetch_all(st.db.pool())
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| BindingOut {
                id: r.get("id"),
                role_id: r.get("role_id"),
                subject: Ref {
                    kind: r.get("subject_kind"),
                    id: r.get("subject_id"),
                },
                scope: Ref {
                    kind: r.get("scope_kind"),
                    id: r.get("scope_id"),
                },
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
pub struct CreateBinding {
    role_id: String,
    subject: Ref,
    scope: Ref,
}

pub async fn create_binding(
    State(st): State<AppState>,
    user: CurrentUser,
    Path(eid): Path<String>,
    Json(req): Json<CreateBinding>,
) -> ApiResult<Created> {
    st.require(&user, &eid, Target::Entity, Permissions::MANAGE_ACCESS)
        .await?;
    if st.db.role_permissions(&eid, &req.role_id).await?.is_none() {
        return Err(ApiError::BadRequest("rôle inconnu".into()));
    }
    match req.subject.kind.as_str() {
        "user" if st.db.is_member(&eid, &req.subject.id).await? => {}
        "user" => {
            return Err(ApiError::BadRequest(
                "l'utilisateur n'est pas membre de l'entité".into(),
            ));
        }
        "group" => group_in_entity(&st, &eid, &req.subject.id)
            .await
            .map_err(|_| ApiError::BadRequest("groupe inconnu".into()))?,
        _ => return Err(ApiError::BadRequest("sujet : user ou group".into())),
    }
    let scope = match Scope::from_parts(&req.scope.kind, &req.scope.id) {
        Some(Scope::Fleet(f)) if st.db.fleet_tree(&eid).await?.contains(&f) => Scope::Fleet(f),
        Some(Scope::Fleet(_)) => return Err(ApiError::BadRequest("parc inconnu".into())),
        Some(Scope::Entity) => Scope::Entity,
        Some(Scope::Device(_)) => {
            return Err(ApiError::BadRequest(
                "la portée machine arrive avec l'enrôlement des hosts".into(),
            ));
        }
        None => return Err(ApiError::BadRequest("portée : entity ou fleet".into())),
    };
    let id = insert_binding(
        &st,
        &eid,
        &req.role_id,
        &req.subject.kind,
        &req.subject.id,
        &scope,
    )
    .await?;
    st.audit(
        Some(&eid),
        &user,
        "binding.create",
        &id,
        json!({ "role_id": req.role_id, "subject": req.subject, "scope": { "kind": scope.kind(), "id": scope.id() } }),
    )
    .await?;
    Ok(created(&id))
}

pub async fn delete_binding(
    State(st): State<AppState>,
    user: CurrentUser,
    Path((eid, bid)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    st.require(&user, &eid, Target::Entity, Permissions::MANAGE_ACCESS)
        .await?;
    ensure_admin_remains(&st, &eid, Removal::Binding(&bid)).await?;
    let done = sqlx::query("DELETE FROM role_bindings WHERE entity_id = $1 AND id = $2")
        .bind(&eid)
        .bind(&bid)
        .execute(st.db.pool())
        .await?;
    if done.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    st.audit(Some(&eid), &user, "binding.delete", &bid, json!({}))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------- audit

#[derive(Deserialize)]
pub struct AuditQuery {
    #[serde(default = "default_limit")]
    limit: i64,
}

fn default_limit() -> i64 {
    100
}

#[derive(Serialize)]
pub struct AuditOut {
    at: i64,
    actor_user_id: Option<String>,
    action: String,
    target: String,
    detail: serde_json::Value,
}

pub async fn audit(
    State(st): State<AppState>,
    user: CurrentUser,
    Path(eid): Path<String>,
    Query(q): Query<AuditQuery>,
) -> ApiResult<Json<Vec<AuditOut>>> {
    st.require(&user, &eid, Target::Entity, Permissions::VIEW_AUDIT)
        .await?;
    let rows = sqlx::query(
        "SELECT at, actor_user_id, action, target, detail FROM audit_log \
         WHERE entity_id = $1 ORDER BY at DESC LIMIT $2",
    )
    .bind(&eid)
    .bind(q.limit.clamp(1, 1000))
    .fetch_all(st.db.pool())
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| AuditOut {
                at: r.get("at"),
                actor_user_id: r.get("actor_user_id"),
                action: r.get("action"),
                target: r.get("target"),
                detail: serde_json::from_str(&r.get::<String, _>("detail")).unwrap_or_default(),
            })
            .collect(),
    ))
}

// ---------------------------------------------------------------- utilitaires

async fn user_id_by_email(st: &AppState, email: &str) -> ApiResult<String> {
    sqlx::query("SELECT id FROM users WHERE email = $1")
        .bind(normalize_email(email))
        .fetch_optional(st.db.pool())
        .await?
        .map(|r| r.get("id"))
        .ok_or_else(|| ApiError::BadRequest("aucun utilisateur avec cet e-mail".into()))
}

async fn insert_member(st: &AppState, eid: &str, uid: &str) -> ApiResult<()> {
    sqlx::query("INSERT INTO memberships (entity_id, user_id, created_at) VALUES ($1, $2, $3)")
        .bind(eid)
        .bind(uid)
        .bind(now())
        .execute(st.db.pool())
        .await?;
    Ok(())
}

async fn insert_binding(
    st: &AppState,
    eid: &str,
    role_id: &str,
    subject_kind: &str,
    subject_id: &str,
    scope: &Scope,
) -> ApiResult<String> {
    let id = new_id();
    sqlx::query(
        "INSERT INTO role_bindings (id, entity_id, role_id, subject_kind, subject_id, scope_kind, scope_id, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(&id)
    .bind(eid)
    .bind(role_id)
    .bind(subject_kind)
    .bind(subject_id)
    .bind(scope.kind())
    .bind(scope.id())
    .bind(now())
    .execute(st.db.pool())
    .await?;
    Ok(id)
}

/// Opération qui pourrait retirer le dernier administrateur d'une entité.
enum Removal<'a> {
    Binding(&'a str),
    User(&'a str),
    Group(&'a str),
    GroupMember(&'a str, &'a str),
}

/// Refuse une opération qui laisserait l'entité sans personne capable de
/// gérer les accès (MANAGE_ACCESS au niveau de l'entité).
async fn ensure_admin_remains(st: &AppState, eid: &str, removal: Removal<'_>) -> ApiResult<()> {
    let rows = sqlx::query(
        "SELECT id, role_id, subject_kind, subject_id FROM role_bindings \
         WHERE entity_id = $1 AND scope_kind = 'entity'",
    )
    .bind(eid)
    .fetch_all(st.db.pool())
    .await?;
    for r in rows {
        let bid: String = r.get("id");
        if matches!(removal, Removal::Binding(b) if b == bid) {
            continue;
        }
        let role: String = r.get("role_id");
        let grants_admin = st
            .db
            .role_permissions(eid, &role)
            .await?
            .is_some_and(|p| p.contains(Permissions::MANAGE_ACCESS));
        if !grants_admin {
            continue;
        }
        let subject: String = r.get("subject_id");
        let kind: String = r.get("subject_kind");
        let still_admin = match kind.as_str() {
            "user" => !matches!(removal, Removal::User(u) if u == subject),
            "group" => {
                if matches!(removal, Removal::Group(g) if g == subject) {
                    false
                } else {
                    let members =
                        sqlx::query("SELECT user_id FROM group_members WHERE group_id = $1")
                            .bind(&subject)
                            .fetch_all(st.db.pool())
                            .await?;
                    members.iter().any(|m| {
                        let uid: String = m.get("user_id");
                        match removal {
                            Removal::User(u) => u != uid,
                            Removal::GroupMember(g, u) => !(g == subject && u == uid),
                            _ => true,
                        }
                    })
                }
            }
            _ => false,
        };
        if still_admin {
            return Ok(());
        }
    }
    Err(ApiError::Conflict(
        "l'entité doit garder au moins un administrateur des accès".into(),
    ))
}
