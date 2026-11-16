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
