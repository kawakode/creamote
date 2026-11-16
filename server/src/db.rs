//! Base de données : SQLite par défaut, PostgreSQL en option.
//!
//! Les deux moteurs passent par le pilote `Any` de sqlx, avec des requêtes
//! SQL portables. Règles à respecter dans les requêtes :
//! - paramètres `$1, $2…` dans l'ordre d'apparition, chacun une seule fois
//!   (SQLite les lie par position d'apparition) ;
//! - entiers en `i64`, booléens stockés en 0/1, identifiants en UUID texte,
//!   horodatages en secondes Unix.

use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use sqlx::any::{AnyConnectOptions, AnyPoolOptions};
use sqlx::{AnyPool, Row};

use crate::rbac::{self, FleetTree, Grant, Permissions, Scope};

static SQLITE_MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/sqlite");
static POSTGRES_MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/postgres");

#[derive(Clone)]
pub struct Db {
    pool: AnyPool,
}

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

impl Db {
    /// `sqlite://chemin.db`, `sqlite::memory:` ou `postgres://…`.
    pub async fn connect(url: &str) -> anyhow::Result<Self> {
        sqlx::any::install_default_drivers();
        let is_sqlite = url.starts_with("sqlite:");
        let url = if is_sqlite && !url.contains(":memory:") && !url.contains("mode=") {
            let sep = if url.contains('?') { '&' } else { '?' };
            format!("{url}{sep}mode=rwc")
        } else {
            url.to_owned()
        };
        let opts = AnyConnectOptions::from_str(&url)?;
        let mut pool = AnyPoolOptions::new();
        if url.contains(":memory:") {
            // Une base mémoire n'existe que dans sa connexion.
            pool = pool
                .max_connections(1)
                .min_connections(1)
                .idle_timeout(None)
                .max_lifetime(None);
        }
        let pool = pool.connect_with(opts).await?;
        if is_sqlite {
            SQLITE_MIGRATIONS.run(&pool).await?;
        } else {
            POSTGRES_MIGRATIONS.run(&pool).await?;
        }
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &AnyPool {
        &self.pool
    }

    /// Crée un utilisateur. Retourne son identifiant.
    pub async fn create_user(
        &self,
        email: &str,
        display_name: &str,
        password: &str,
        superadmin: bool,
    ) -> sqlx::Result<String> {
        let id = new_id();
        sqlx::query(
            "INSERT INTO users (id, email, display_name, password_hash, is_superadmin, disabled, created_at) \
             VALUES ($1, $2, $3, $4, $5, 0, $6)",
        )
        .bind(&id)
        .bind(normalize_email(email))
        .bind(display_name)
        .bind(crate::auth::hash_password(password))
        .bind(i64::from(superadmin))
        .bind(now())
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn audit(
        &self,
        entity_id: Option<&str>,
        actor: Option<&str>,
        action: &str,
        target: &str,
        detail: serde_json::Value,
    ) -> sqlx::Result<()> {
        sqlx::query(
            "INSERT INTO audit_log (id, at, entity_id, actor_user_id, action, target, detail) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(new_id())
        .bind(now())
        .bind(entity_id)
        .bind(actor)
        .bind(action)
        .bind(target)
        .bind(detail.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn is_member(&self, entity_id: &str, user_id: &str) -> sqlx::Result<bool> {
        let row = sqlx::query("SELECT 1 FROM memberships WHERE entity_id = $1 AND user_id = $2")
            .bind(entity_id)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    pub async fn fleet_tree(&self, entity_id: &str) -> sqlx::Result<FleetTree> {
        let rows = sqlx::query("SELECT id, parent_id FROM fleets WHERE entity_id = $1")
            .bind(entity_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(FleetTree::new(rows.into_iter().map(|r| {
            (
                r.get::<String, _>("id"),
                r.get::<Option<String>, _>("parent_id"),
            )
        })))
    }

    /// Permissions d'un rôle (intégré ou personnalisé de l'entité).
    pub async fn role_permissions(
        &self,
        entity_id: &str,
        role_id: &str,
    ) -> sqlx::Result<Option<Permissions>> {
        if let Some(r) = rbac::builtin_role(role_id) {
            return Ok(Some(r.permissions));
        }
        let row = sqlx::query("SELECT permissions FROM roles WHERE entity_id = $1 AND id = $2")
            .bind(entity_id)
            .bind(role_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| Permissions::from_bits_truncate(r.get::<i64, _>("permissions") as u64)))
    }

    /// Attributions qui concernent un utilisateur dans une entité, directement
    /// ou via ses groupes de sécurité.
    pub async fn grants_for(&self, entity_id: &str, user_id: &str) -> sqlx::Result<Vec<Grant>> {
        let rows = sqlx::query(
            "SELECT role_id, scope_kind, scope_id FROM role_bindings WHERE entity_id = $1 AND ( \
               (subject_kind = 'user' AND subject_id = $2) OR \
               (subject_kind = 'group' AND subject_id IN \
                  (SELECT group_id FROM group_members WHERE user_id = $3)))",
        )
        .bind(entity_id)
        .bind(user_id)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        let mut grants = Vec::with_capacity(rows.len());
        for r in rows {
            let role_id: String = r.get("role_id");
            let Some(permissions) = self.role_permissions(entity_id, &role_id).await? else {
                continue;
            };
            let Some(scope) = Scope::from_parts(r.get("scope_kind"), r.get("scope_id")) else {
                continue;
            };
            grants.push(Grant { permissions, scope });
        }
        Ok(grants)
    }
}

/// Résultat d'une demande d'enrôlement.
#[derive(Debug, PartialEq, Eq)]
pub enum Enrollment {
    Enrolled {
        device_row_id: String,
        entity_id: String,
        entity_name: String,
        fleet_name: String,
    },
    InvalidToken,
    AlreadyEnrolled,
}

impl Db {
    /// Enrôle une machine (identité déjà prouvée) avec un jeton d'enrôlement.
    /// Le jeton est consommé de façon atomique.
    pub async fn enroll_device(
        &self,
        token: &str,
        signing_key_hex: &str,
        device_id: &str,
        name: &str,
        platform: &str,
    ) -> sqlx::Result<Enrollment> {
        let mut tx = self.pool.begin().await?;
        let hash = crate::auth::token_hash(token.trim());
        let row = sqlx::query(
            "SELECT t.id, t.entity_id, t.fleet_id, e.name AS entity_name, f.name AS fleet_name \
             FROM enrollment_tokens t JOIN entities e ON e.id = t.entity_id \
             JOIN fleets f ON f.id = t.fleet_id \
             WHERE t.token_hash = $1 AND t.expires_at > $2 AND t.uses_left > 0",
        )
        .bind(&hash)
        .bind(now())
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            return Ok(Enrollment::InvalidToken);
        };
        let known = sqlx::query("SELECT 1 FROM devices WHERE signing_key = $1")
            .bind(signing_key_hex)
            .fetch_optional(&mut *tx)
            .await?;
        if known.is_some() {
            return Ok(Enrollment::AlreadyEnrolled);
        }
        let token_id: String = row.get("id");
        let used = sqlx::query(
            "UPDATE enrollment_tokens SET uses_left = uses_left - 1 WHERE id = $1 AND uses_left > 0",
        )
        .bind(&token_id)
        .execute(&mut *tx)
        .await?;
        if used.rows_affected() != 1 {
            return Ok(Enrollment::InvalidToken);
        }
        let id = new_id();
        let entity_id: String = row.get("entity_id");
        let at = now();
        sqlx::query(
            "INSERT INTO devices (id, entity_id, fleet_id, device_id, signing_key, name, platform, enrolled_at, last_seen) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(&id)
        .bind(&entity_id)
        .bind(row.get::<String, _>("fleet_id"))
        .bind(device_id)
        .bind(signing_key_hex)
        .bind(name)
        .bind(platform)
        .bind(at)
        .bind(at)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Enrollment::Enrolled {
            device_row_id: id,
            entity_id,
            entity_name: row.get("entity_name"),
            fleet_name: row.get("fleet_name"),
        })
    }

    /// Note la dernière présence d'une machine enrôlée.
    pub async fn touch_device(&self, signing_key_hex: &str) -> sqlx::Result<()> {
        sqlx::query("UPDATE devices SET last_seen = $1 WHERE signing_key = $2")
            .bind(now())
            .bind(signing_key_hex)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sqlite_memory_migrates_and_stores_users() {
        let db = Db::connect("sqlite::memory:").await.unwrap();
        let id = db
            .create_user(" Admin@Example.org ", "Admin", "mot de passe long", true)
            .await
            .unwrap();
        let row = sqlx::query("SELECT email, is_superadmin FROM users WHERE id = $1")
            .bind(&id)
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(row.get::<String, _>("email"), "admin@example.org");
        assert_eq!(row.get::<i64, _>("is_superadmin"), 1);
        assert!(
            db.create_user("admin@example.org", "Bis", "mot de passe long", false)
                .await
                .is_err(),
            "e-mail unique"
        );
    }
}
