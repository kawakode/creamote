//! Tests de l'API de gestion de parc, de bout en bout via le routeur HTTP.
//!
//! Base : `CREAMOTE_TEST_DATABASE_URL` si définie (PostgreSQL en CI), sinon
//! SQLite en mémoire.

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use creamote_server::api;
use creamote_server::db::Db;

const PASSWORD: &str = "mot de passe très long";

struct Api {
    app: Router,
    db: Db,
    /// Suffixe unique : plusieurs tests peuvent partager une base PostgreSQL.
    tag: String,
}

impl Api {
    async fn new() -> Self {
        let url = std::env::var("CREAMOTE_TEST_DATABASE_URL")
            .unwrap_or_else(|_| "sqlite::memory:".to_owned());
        let db = Db::connect(&url).await.unwrap();
        Self {
            app: api::router(db.clone()),
            db,
            tag: uuid::Uuid::new_v4().simple().to_string(),
        }
    }

    fn email(&self, name: &str) -> String {
        format!("{name}-{}@example.org", self.tag)
    }

    async fn user(&self, name: &str, superadmin: bool) -> (String, String) {
        let id = self
            .db
            .create_user(&self.email(name), name, PASSWORD, superadmin)
            .await
            .unwrap();
        let (status, body) = self
            .call(
                Method::POST,
                "/api/v1/auth/login",
                None,
                Some(json!({ "email": self.email(name), "password": PASSWORD })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        (id, body["token"].as_str().unwrap().to_owned())
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut req = Request::builder().method(method).uri(path);
        if let Some(t) = token {
            req = req.header("authorization", format!("Bearer {t}"));
        }
        let req = match body {
            Some(b) => req
                .header("content-type", "application/json")
                .body(Body::from(b.to_string())),
            None => req.body(Body::empty()),
        }
        .unwrap();
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, value)
    }

    async fn post(&self, path: &str, token: &str, body: Value) -> (StatusCode, Value) {
        self.call(Method::POST, path, Some(token), Some(body)).await
    }

    async fn get(&self, path: &str, token: &str) -> (StatusCode, Value) {
        self.call(Method::GET, path, Some(token), None).await
    }

    async fn delete(&self, path: &str, token: &str) -> StatusCode {
        self.call(Method::DELETE, path, Some(token), None).await.0
    }

    /// Entité créée par un super-admin, avec `owner` comme propriétaire.
    async fn entity(&self, owner: &str) -> String {
        let (_, root) = self.user("root", true).await;
        let (s, b) = self
            .post(
                "/api/v1/entities",
                &root,
                json!({ "name": "ACME", "owner_email": self.email(owner) }),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        b["id"].as_str().unwrap().to_owned()
    }
}

fn id(v: &Value) -> String {
    v["id"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn login_me_logout() {
    let api = Api::new().await;
    let (_, token) = api.user("alice", false).await;

    let (s, _) = api
        .call(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some(json!({ "email": api.email("alice"), "password": "mauvais mot de passe" })),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = api
        .call(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some(json!({ "email": api.email("personne"), "password": PASSWORD })),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    let (s, me) = api.get("/api/v1/me", &token).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(me["user"]["email"], api.email("alice"));
    assert_eq!(me["entities"], json!([]));

    let (s, _) = api
        .call(Method::POST, "/api/v1/auth/logout", Some(&token), None)
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(
        api.get("/api/v1/me", &token).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        api.get("/api/v1/me", "crm_faux").await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn only_superadmin_creates_users_and_entities() {
    let api = Api::new().await;
    let (_, alice) = api.user("alice", false).await;
    let (_, root) = api.user("root", true).await;

    let new_user =
        json!({ "email": api.email("bob"), "display_name": "Bob", "password": PASSWORD });
    assert_eq!(
        api.post("/api/v1/users", &alice, new_user.clone()).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        api.post("/api/v1/entities", &alice, json!({ "name": "X" }))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        api.post("/api/v1/users", &root, new_user.clone()).await.0,
        StatusCode::CREATED
    );
    assert_eq!(
        api.post("/api/v1/users", &root, new_user).await.0,
        StatusCode::CONFLICT
    );
    let short =
        json!({ "email": api.email("carol"), "display_name": "Carol", "password": "court" });
    assert_eq!(
        api.post("/api/v1/users", &root, short).await.0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn entity_is_hidden_from_non_members() {
    let api = Api::new().await;
    let (_, alice) = api.user("alice", false).await;
    let (bob_id, bob) = api.user("bob", false).await;
    let eid = api.entity("alice").await;

    let (_, me) = api.get("/api/v1/me", &alice).await;
    assert_eq!(me["entities"][0]["id"], eid.as_str());
    assert!(me["entities"][0]["permissions"].as_array().unwrap().len() >= 8);

    assert_eq!(
        api.get(&format!("/api/v1/entities/{eid}"), &bob).await.0,
        StatusCode::NOT_FOUND
    );

    let (s, _) = api
        .post(
            &format!("/api/v1/entities/{eid}/members"),
            &alice,
            json!({ "email": api.email("bob") }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(
        api.get(&format!("/api/v1/entities/{eid}"), &bob).await.0,
        StatusCode::OK
    );
    // Membre sans rôle : lecture seule.
    assert_eq!(
        api.post(
            &format!("/api/v1/entities/{eid}/fleets"),
            &bob,
            json!({ "name": "Siège" })
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let (_, members) = api
        .get(&format!("/api/v1/entities/{eid}/members"), &bob)
        .await;
    assert!(
        members
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["user_id"] == bob_id.as_str())
    );
}

#[tokio::test]
async fn fleet_role_via_group_applies_to_subtree_only() {
    let api = Api::new().await;
    let (_, alice) = api.user("alice", false).await;
    let (bob_id, bob) = api.user("bob", false).await;
    let eid = api.entity("alice").await;
    let e = |p: &str| format!("/api/v1/entities/{eid}{p}");

    let siege = id(&api
        .post(&e("/fleets"), &alice, json!({ "name": "Siège" }))
        .await
        .1);
    let compta = id(&api
        .post(
            &e("/fleets"),
            &alice,
            json!({ "name": "Compta", "parent_id": siege }),
        )
        .await
        .1);
    let atelier = id(&api
        .post(&e("/fleets"), &alice, json!({ "name": "Atelier" }))
        .await
        .1);

    api.post(&e("/members"), &alice, json!({ "email": api.email("bob") }))
        .await;
    let techs = id(&api
        .post(&e("/groups"), &alice, json!({ "name": "Techs" }))
        .await
        .1);
    let (s, _) = api
        .post(
            &e(&format!("/groups/{techs}/members")),
            &alice,
            json!({ "user_id": bob_id }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, b) = api
        .post(
            &e("/bindings"),
            &alice,
            json!({ "role_id": "fleet-admin", "subject": { "kind": "group", "id": techs },
                    "scope": { "kind": "fleet", "id": compta } }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");

    // Bob gère Compta et en dessous, pas ailleurs.
    let sub = |parent: &str| json!({ "name": "Postes", "parent_id": parent });
    assert_eq!(
        api.post(&e("/fleets"), &bob, sub(&compta)).await.0,
        StatusCode::CREATED
    );
    assert_eq!(
        api.post(&e("/fleets"), &bob, sub(&atelier)).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        api.post(&e("/fleets"), &bob, sub(&siege)).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        api.post(&e("/fleets"), &bob, json!({ "name": "Racine" }))
            .await
            .0,
        StatusCode::FORBIDDEN
    );

    let (_, p) = api
        .get(&e(&format!("/my-permissions?fleet_id={compta}")), &bob)
        .await;
    assert!(
        p["permissions"]
            .as_array()
            .unwrap()
            .contains(&json!("manage_devices"))
    );
    assert!(
        p["permissions"]
            .as_array()
            .unwrap()
            .contains(&json!("unattended"))
    );
    let (_, p) = api
        .get(&e(&format!("/my-permissions?fleet_id={atelier}")), &bob)
        .await;
    assert_eq!(p["permissions"], json!([]));

    // Sorti du groupe, Bob perd ses droits.
    assert_eq!(
        api.delete(&e(&format!("/groups/{techs}/members/{bob_id}")), &alice)
            .await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        api.post(&e("/fleets"), &bob, sub(&compta)).await.0,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn fleets_cannot_form_cycles_or_lose_children() {
    let api = Api::new().await;
    let (_, alice) = api.user("alice", false).await;
    let eid = api.entity("alice").await;
    let e = |p: &str| format!("/api/v1/entities/{eid}{p}");

    let a = id(&api
        .post(&e("/fleets"), &alice, json!({ "name": "A" }))
        .await
        .1);
    let b = id(&api
        .post(
            &e("/fleets"),
            &alice,
            json!({ "name": "B", "parent_id": a }),
        )
        .await
        .1);

    let (s, _) = api
        .call(
            Method::PATCH,
            &e(&format!("/fleets/{a}")),
            Some(&alice),
            Some(json!({ "parent_id": b })),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(
        api.delete(&e(&format!("/fleets/{a}")), &alice).await,
        StatusCode::CONFLICT
    );

    let (s, _) = api
        .call(
            Method::PATCH,
            &e(&format!("/fleets/{b}")),
            Some(&alice),
            Some(json!({ "parent_id": null, "name": "B2" })),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(
        api.delete(&e(&format!("/fleets/{a}")), &alice).await,
        StatusCode::NO_CONTENT
    );
    let (_, fleets) = api.get(&e("/fleets"), &alice).await;
    assert_eq!(
        fleets,
        json!([{ "id": b, "name": "B2", "parent_id": null }])
    );
}

#[tokio::test]
async fn entity_always_keeps_an_access_admin() {
    let api = Api::new().await;
    let (alice_id, alice) = api.user("alice", false).await;
    let (bob_id, _) = api.user("bob", false).await;
    let eid = api.entity("alice").await;
    let e = |p: &str| format!("/api/v1/entities/{eid}{p}");

    let (_, bindings) = api.get(&e("/bindings"), &alice).await;
    let owner_binding = bindings[0]["id"].as_str().unwrap().to_owned();
    assert_eq!(
        api.delete(&e(&format!("/bindings/{owner_binding}")), &alice)
            .await,
        StatusCode::CONFLICT
    );
    assert_eq!(
        api.delete(&e(&format!("/members/{alice_id}")), &alice)
            .await,
        StatusCode::CONFLICT
    );

    api.post(&e("/members"), &alice, json!({ "email": api.email("bob") }))
        .await;
    let (s, _) = api
        .post(
            &e("/bindings"),
            &alice,
            json!({ "role_id": "owner", "subject": { "kind": "user", "id": bob_id },
                    "scope": { "kind": "entity" } }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(
        api.delete(&e(&format!("/bindings/{owner_binding}")), &alice)
            .await,
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn custom_roles_and_audit() {
    let api = Api::new().await;
    let (_, alice) = api.user("alice", false).await;
    let (bob_id, bob) = api.user("bob", false).await;
    let eid = api.entity("alice").await;
    let e = |p: &str| format!("/api/v1/entities/{eid}{p}");

    let (s, _) = api
        .post(
            &e("/roles"),
            &alice,
            json!({ "name": "X", "permissions": ["view_screen", "voler"] }),
        )
        .await;
    assert!(s.is_client_error());

    let (s, r) = api
        .post(
            &e("/roles"),
            &alice,
            json!({ "name": "Support N1", "permissions": ["view_screen", "clipboard"] }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED);
    let role = id(&r);
    api.post(&e("/members"), &alice, json!({ "email": api.email("bob") }))
        .await;
    api.post(
        &e("/bindings"),
        &alice,
        json!({ "role_id": role, "subject": { "kind": "user", "id": bob_id }, "scope": { "kind": "entity" } }),
    )
    .await;
    let (_, p) = api.get(&e("/my-permissions"), &bob).await;
    assert_eq!(p["permissions"], json!(["view_screen", "clipboard"]));
    assert_eq!(
        api.delete(&e(&format!("/roles/{role}")), &alice).await,
        StatusCode::CONFLICT
    );

    // Journal d'audit : réservé à view_audit.
    assert_eq!(api.get(&e("/audit"), &bob).await.0, StatusCode::FORBIDDEN);
    let (s, log) = api.get(&e("/audit"), &alice).await;
    assert_eq!(s, StatusCode::OK);
    let actions: Vec<&str> = log
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["action"].as_str().unwrap())
        .collect();
    for expected in [
        "entity.create",
        "role.create",
        "member.add",
        "binding.create",
    ] {
        assert!(
            actions.contains(&expected),
            "{expected} absent de {actions:?}"
        );
    }
}
