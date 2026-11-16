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

use std::sync::Arc;

use creamote_crypto::DeviceIdentity;
use creamote_net::ticket;
use creamote_server::api;
use creamote_server::db::{Db, Enrollment};

const PASSWORD: &str = "mot de passe très long";

struct Api {
    app: Router,
    db: Db,
    ticket_key: Arc<DeviceIdentity>,
    /// Suffixe unique : plusieurs tests peuvent partager une base PostgreSQL.
    tag: String,
}

impl Api {
    async fn new() -> Self {
        let url = std::env::var("CREAMOTE_TEST_DATABASE_URL")
            .unwrap_or_else(|_| "sqlite::memory:".to_owned());
        let db = Db::connect(&url).await.unwrap();
        let services = api::Services::ephemeral();
        let ticket_key = services.ticket_key.clone();
        Self {
            app: api::router(db.clone(), services),
            db,
            ticket_key,
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

    async fn patch(&self, path: &str, token: &str, body: Value) -> StatusCode {
        self.call(Method::PATCH, path, Some(token), Some(body))
            .await
            .0
    }

    /// Enrôle une machine comme le ferait le rendezvous.
    async fn enroll(&self, token: &str, host: &DeviceIdentity) -> Enrollment {
        self.db
            .enroll_device(
                token,
                &hex(host.public().signing_key()),
                &format!("{:09}", host.device_id().as_u32()),
                "PC-Compta-01",
                "linux",
            )
            .await
            .unwrap()
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

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
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

#[tokio::test]
async fn enrollment_tokens_are_scoped_and_consumed() {
    let api = Api::new().await;
    let (_, alice) = api.user("alice", false).await;
    let (_, bob) = api.user("bob", false).await;
    let eid = api.entity("alice").await;
    let e = |p: &str| format!("/api/v1/entities/{eid}{p}");
    let fleet = id(&api
        .post(&e("/fleets"), &alice, json!({ "name": "Compta" }))
        .await
        .1);
    api.post(&e("/members"), &alice, json!({ "email": api.email("bob") }))
        .await;

    // Bob, simple membre, ne peut pas créer de jeton.
    let req = json!({ "fleet_id": fleet, "uses": 2 });
    assert_eq!(
        api.post(&e("/enrollment-tokens"), &bob, req.clone())
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let (s, t) = api.post(&e("/enrollment-tokens"), &alice, req).await;
    assert_eq!(s, StatusCode::CREATED, "{t}");
    let token = t["token"].as_str().unwrap().to_owned();
    assert!(token.starts_with("cre_"));
    let (_, list) = api.get(&e("/enrollment-tokens"), &alice).await;
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert!(
        list[0].get("token").is_none(),
        "la valeur n'est jamais relistée"
    );
    assert_eq!(api.get(&e("/enrollment-tokens"), &bob).await.1, json!([]));

    let (a, b, c) = (
        DeviceIdentity::generate(),
        DeviceIdentity::generate(),
        DeviceIdentity::generate(),
    );
    assert!(matches!(
        api.enroll(&token, &a).await,
        Enrollment::Enrolled { .. }
    ));
    assert_eq!(api.enroll(&token, &a).await, Enrollment::AlreadyEnrolled);
    assert!(matches!(
        api.enroll(&token, &b).await,
        Enrollment::Enrolled { .. }
    ));
    assert_eq!(
        api.enroll(&token, &c).await,
        Enrollment::InvalidToken,
        "jeton épuisé"
    );
    assert_eq!(api.enroll("cre_faux", &c).await, Enrollment::InvalidToken);

    // Jeton expiré.
    let (_, t2) = api
        .post(
            &e("/enrollment-tokens"),
            &alice,
            json!({ "fleet_id": fleet }),
        )
        .await;
    sqlx::query("UPDATE enrollment_tokens SET expires_at = 1 WHERE id = $1")
        .bind(id(&t2))
        .execute(api.db.pool())
        .await
        .unwrap();
    assert_eq!(
        api.enroll(t2["token"].as_str().unwrap(), &c).await,
        Enrollment::InvalidToken
    );

    // Révocation.
    let (_, t3) = api
        .post(
            &e("/enrollment-tokens"),
            &alice,
            json!({ "fleet_id": fleet }),
        )
        .await;
    assert_eq!(
        api.delete(&e(&format!("/enrollment-tokens/{}", id(&t3))), &bob)
            .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        api.delete(&e(&format!("/enrollment-tokens/{}", id(&t3))), &alice)
            .await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        api.enroll(t3["token"].as_str().unwrap(), &c).await,
        Enrollment::InvalidToken
    );

    // Un parc qui contient des machines ne peut pas être supprimé.
    assert_eq!(
        api.delete(&e(&format!("/fleets/{fleet}")), &alice).await,
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn devices_and_tickets_follow_rbac() {
    let api = Api::new().await;
    let (_, alice) = api.user("alice", false).await;
    let (bob_id, bob) = api.user("bob", false).await;
    let (_, carol) = api.user("carol", false).await;
    let eid = api.entity("alice").await;
    let e = |p: &str| format!("/api/v1/entities/{eid}{p}");
    let compta = id(&api
        .post(&e("/fleets"), &alice, json!({ "name": "Compta" }))
        .await
        .1);
    let atelier = id(&api
        .post(&e("/fleets"), &alice, json!({ "name": "Atelier" }))
        .await
        .1);
    api.post(&e("/members"), &alice, json!({ "email": api.email("bob") }))
        .await;

    let (_, t) = api
        .post(
            &e("/enrollment-tokens"),
            &alice,
            json!({ "fleet_id": compta }),
        )
        .await;
    let host = DeviceIdentity::generate();
    assert!(matches!(
        api.enroll(t["token"].as_str().unwrap(), &host).await,
        Enrollment::Enrolled { .. }
    ));

    let (s, list) = api.get(&e("/devices"), &alice).await;
    assert_eq!(s, StatusCode::OK);
    let devices = list.as_array().unwrap();
    assert_eq!(devices.len(), 1);
    let dev = &devices[0];
    let did = id(dev);
    assert_eq!(dev["device_id"], json!(host.device_id().to_string()));
    assert_eq!(dev["fleet_id"], json!(compta));
    assert_eq!(dev["online"], json!(false));
    assert_eq!(dev["platform"], json!("linux"));

    // Bob ne voit rien tant qu'aucun rôle ne le lui permet.
    assert_eq!(api.get(&e("/devices"), &bob).await.1, json!([]));
    assert_eq!(
        api.get(&e(&format!("/devices/{did}")), &bob).await.0,
        StatusCode::NOT_FOUND
    );
    let viewer = DeviceIdentity::generate();
    let ticket_req = json!({
        "device_id": host.device_id().to_string(),
        "viewer_key": hex(viewer.public().signing_key()),
    });
    assert_eq!(
        api.post("/api/v1/tickets", &bob, ticket_req.clone())
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        api.post("/api/v1/tickets", &carol, ticket_req.clone())
            .await
            .0,
        StatusCode::NOT_FOUND
    );

    // Rôle technicien sur cette seule machine.
    let (s, b) = api
        .post(
            &e("/bindings"),
            &alice,
            json!({ "role_id": "technician", "subject": { "kind": "user", "id": bob_id },
                    "scope": { "kind": "device", "id": did } }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    let (s, b) = api
        .post(
            &e("/bindings"),
            &alice,
            json!({ "role_id": "technician", "subject": { "kind": "user", "id": bob_id },
                    "scope": { "kind": "device", "id": "inconnue" } }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
    let (_, list) = api.get(&e("/devices"), &bob).await;
    assert_eq!(
        list[0]["permissions"],
        json!(["view_screen", "control", "clipboard", "file_transfer"])
    );
    let (_, p) = api
        .get(&e(&format!("/my-permissions?device={did}")), &bob)
        .await;
    assert_eq!(p["permissions"], list[0]["permissions"]);

    // Ticket : signé par la clé du serveur, lié au host et au viewer.
    let (s, tk) = api.post("/api/v1/tickets", &bob, ticket_req.clone()).await;
    assert_eq!(s, StatusCode::OK, "{tk}");
    let signed = unhex(tk["ticket"].as_str().unwrap());
    let server_key = api.ticket_key.public().signing_key();
    let t = ticket::verify(
        &signed,
        server_key,
        host.public(),
        viewer.public(),
        ticket::unix_now(),
    )
    .unwrap();
    assert_eq!(t.user_email, api.email("bob"));
    assert_eq!(t.entity_id, eid);
    // Sans `unattended`, un host enrôlé refuse la session sans surveillance.
    let enrollment = ticket::Enrollment {
        ticket_key: *server_key,
        server: String::new(),
        server_pin: String::new(),
        entity_name: String::new(),
        fleet_name: String::new(),
    };
    assert!(matches!(
        ticket::decide(
            Some(&enrollment),
            &signed,
            host.public(),
            viewer.public(),
            ticket::unix_now()
        ),
        ticket::Decision::Decline(ticket::TicketError::Insufficient(_))
    ));
    let (s, _) = api
        .post(
            "/api/v1/tickets",
            &bob,
            json!({ "device_id": "pas un id", "viewer_key": hex(viewer.public().signing_key()) }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Bob (technicien) ne gère pas la machine ; Alice peut la renommer et la
    // déplacer.
    assert_eq!(
        api.patch(&e(&format!("/devices/{did}")), &bob, json!({ "name": "x" }))
            .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        api.patch(
            &e(&format!("/devices/{did}")),
            &alice,
            json!({ "name": "Poste 1", "fleet_id": atelier })
        )
        .await,
        StatusCode::NO_CONTENT
    );
    let (_, d) = api.get(&e(&format!("/devices/{did}")), &alice).await;
    assert_eq!(
        (d["name"].clone(), d["fleet_id"].clone()),
        (json!("Poste 1"), json!(atelier))
    );

    // Le ticket d'Alice (propriétaire) inclut `unattended`.
    let (_, tk) = api
        .post("/api/v1/tickets", &alice, ticket_req.clone())
        .await;
    let signed = unhex(tk["ticket"].as_str().unwrap());
    assert!(matches!(
        ticket::decide(
            Some(&enrollment),
            &signed,
            host.public(),
            viewer.public(),
            ticket::unix_now()
        ),
        ticket::Decision::Accept(_)
    ));

    // Machine retirée : plus de ticket, attribution supprimée.
    assert_eq!(
        api.delete(&e(&format!("/devices/{did}")), &bob).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        api.delete(&e(&format!("/devices/{did}")), &alice).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        api.post("/api/v1/tickets", &alice, ticket_req).await.0,
        StatusCode::NOT_FOUND
    );
    let (_, bindings) = api.get(&e("/bindings"), &alice).await;
    assert!(
        bindings
            .as_array()
            .unwrap()
            .iter()
            .all(|b| b["scope"]["kind"] != "device")
    );
    let (_, audit) = api.get(&e("/audit"), &alice).await;
    let actions: Vec<_> = audit
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["action"].as_str().unwrap().to_owned())
        .collect();
    for a in [
        "enrollment_token.create",
        "ticket.issue",
        "device.update",
        "device.delete",
    ] {
        assert!(actions.iter().any(|x| x == a), "{a} absent de {actions:?}");
    }
}

#[tokio::test]
async fn console_is_served_with_strict_headers() {
    let api = Api::new().await;
    for (path, ty) in [
        ("/", "text/html"),
        ("/app.js", "text/javascript"),
        ("/app.css", "text/css"),
        ("/icon.svg", "image/svg+xml"),
    ] {
        let req = Request::builder().uri(path).body(Body::empty()).unwrap();
        let resp = api.app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{path}");
        let h = resp.headers();
        assert!(
            h["content-type"].to_str().unwrap().starts_with(ty),
            "{path}"
        );
        let csp = h["content-security-policy"].to_str().unwrap();
        assert!(csp.contains("default-src 'none'") && csp.contains("frame-ancestors 'none'"));
        assert_eq!(h["x-content-type-options"], "nosniff");
    }
    // La page charge le script et la feuille de style de la même origine.
    let req = Request::builder().uri("/").body(Body::empty()).unwrap();
    let body = api.app.clone().oneshot(req).await.unwrap().into_body();
    let html = String::from_utf8(body.collect().await.unwrap().to_bytes().to_vec()).unwrap();
    assert!(html.contains(r#"src="app.js""#) && html.contains(r#"href="app.css""#));
    assert!(
        !html.contains("http://") && !html.contains("https://"),
        "aucune ressource externe"
    );

    // Informations d'enrôlement : authentification requise.
    assert_eq!(
        api.call(Method::GET, "/api/v1/server-info", None, None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let (_, token) = api.user("alice", false).await;
    let (s, info) = api.get("/api/v1/server-info", &token).await;
    assert_eq!(s, StatusCode::OK);
    assert!(info.get("server_pin").is_some() && info.get("version").is_some());
}

async fn login_with(
    api: &Api,
    name: &str,
    password: &str,
    code: Option<&str>,
) -> (StatusCode, Value) {
    let mut body = json!({ "email": api.email(name), "password": password });
    if let Some(c) = code {
        body["totp_code"] = json!(c);
    }
    api.call(Method::POST, "/api/v1/auth/login", None, Some(body))
        .await
}

fn current_code(secret: &str) -> String {
    use creamote_server::totp;
    let key = totp::base32_decode(secret).unwrap();
    let step = creamote_server::db::now() / totp::STEP_SECS;
    format!("{:06}", totp::hotp(&key, step as u64))
}

#[tokio::test]
async fn login_attempts_are_rate_limited_per_account() {
    let api = Api::new().await;
    api.user("alice", false).await;
    api.user("bob", false).await;
    for _ in 0..5 {
        assert_eq!(
            login_with(&api, "alice", "mauvais mot de passe", None)
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
    }
    // Même le bon mot de passe est refusé pendant le blocage.
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "email": api.email("alice"), "password": PASSWORD }).to_string(),
        ))
        .unwrap();
    let resp = api.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry: u64 = resp.headers()["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(retry > 0 && retry <= 15 * 60);
    // Les autres comptes ne sont pas touchés.
    assert_eq!(
        login_with(&api, "bob", PASSWORD, None).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn totp_enrollment_login_and_recovery() {
    let api = Api::new().await;
    let (alice_id, alice) = api.user("alice", false).await;
    let (_, root) = api.user("root", true).await;

    let (s, _) = api
        .post(
            "/api/v1/me/totp/setup",
            &alice,
            json!({ "password": "pas le bon" }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, setup) = api
        .post(
            "/api/v1/me/totp/setup",
            &alice,
            json!({ "password": PASSWORD }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{setup}");
    let secret = setup["secret"].as_str().unwrap().to_owned();
    assert!(
        setup["otpauth_uri"]
            .as_str()
            .unwrap()
            .starts_with("otpauth://totp/Creamote:")
    );
    assert!(setup["qr_svg"].as_str().unwrap().contains("<svg"));
    // Pas encore active : la connexion ne demande rien de plus.
    assert_eq!(
        login_with(&api, "alice", PASSWORD, None).await.0,
        StatusCode::OK
    );

    let (s, _) = api
        .post(
            "/api/v1/me/totp/enable",
            &alice,
            json!({ "code": "000000" }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, en) = api
        .post(
            "/api/v1/me/totp/enable",
            &alice,
            json!({ "code": current_code(&secret) }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{en}");
    let codes: Vec<String> = serde_json::from_value(en["recovery_codes"].clone()).unwrap();
    assert_eq!(codes.len(), 10);
    let (_, me) = api.get("/api/v1/me", &alice).await;
    assert_eq!(
        (
            me["totp_enabled"].clone(),
            me["recovery_codes_left"].clone()
        ),
        (json!(true), json!(10))
    );

    // Connexion : code requis, code faux refusé, code déjà utilisé refusé.
    let (s, b) = login_with(&api, "alice", PASSWORD, None).await;
    assert_eq!(
        (s, b["error"].clone()),
        (StatusCode::UNAUTHORIZED, json!("totp_required"))
    );
    let (s, b) = login_with(&api, "alice", PASSWORD, Some("123456")).await;
    assert_eq!(
        (s, b["error"].clone()),
        (StatusCode::UNAUTHORIZED, json!("totp_invalid"))
    );
    let (s, _) = login_with(&api, "alice", PASSWORD, Some(&current_code(&secret))).await;
    assert_eq!(
        s,
        StatusCode::UNAUTHORIZED,
        "code consommé à l'activation : pas de rejeu"
    );
    sqlx::query("UPDATE users SET totp_last_step = 0 WHERE id = $1")
        .bind(&alice_id)
        .execute(api.db.pool())
        .await
        .unwrap();
    assert_eq!(
        login_with(&api, "alice", PASSWORD, Some(&current_code(&secret)))
            .await
            .0,
        StatusCode::OK
    );

    // Code de secours : une seule fois, saisie tolérante.
    let messy = codes[0].to_uppercase().replace('-', " ");
    assert_eq!(
        login_with(&api, "alice", PASSWORD, Some(&messy)).await.0,
        StatusCode::OK
    );
    assert_eq!(
        login_with(&api, "alice", PASSWORD, Some(&codes[0])).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (_, me) = api.get("/api/v1/me", &alice).await;
    assert_eq!(me["recovery_codes_left"], json!(9));

    // Désactivation : mot de passe + code.
    let (s, _) = api
        .post(
            "/api/v1/me/totp/disable",
            &alice,
            json!({ "password": PASSWORD, "code": "000000" }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = api
        .post(
            "/api/v1/me/totp/disable",
            &alice,
            json!({ "password": PASSWORD, "code": codes[1] }),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(
        login_with(&api, "alice", PASSWORD, None).await.0,
        StatusCode::OK
    );

    // Réinitialisation par un super-admin (appareil perdu) : sessions révoquées.
    let (_, setup) = api
        .post(
            "/api/v1/me/totp/setup",
            &alice,
            json!({ "password": PASSWORD }),
        )
        .await;
    let secret = setup["secret"].as_str().unwrap().to_owned();
    api.post(
        "/api/v1/me/totp/enable",
        &alice,
        json!({ "code": current_code(&secret) }),
    )
    .await;
    let reset = format!("/api/v1/users/{alice_id}/totp/reset");
    assert_eq!(
        api.post(&reset, &alice, json!({})).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        api.post(&reset, &root, json!({})).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        api.get("/api/v1/me", &alice).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        login_with(&api, "alice", PASSWORD, None).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn address_book_is_private() {
    let api = Api::new().await;
    let (_, alice) = api.user("alice", false).await;
    let (_, bob) = api.user("bob", false).await;
    let book = "/api/v1/me/address-book";

    let (s, _) = api
        .post(
            book,
            &alice,
            json!({ "label": "PC maman", "device_id": "12345" }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, e) = api
        .post(
            book,
            &alice,
            json!({ "label": "PC maman", "device_id": "012345678", "notes": "salon" }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{e}");
    let eid = id(&e);
    let (_, list) = api.get(book, &alice).await;
    assert_eq!(list[0]["device_id"], json!("012 345 678"));
    assert_eq!(list[0]["notes"], json!("salon"));
    assert_eq!(api.get(book, &bob).await.1, json!([]));

    let entry = format!("{book}/{eid}");
    assert_eq!(
        api.patch(&entry, &bob, json!({ "label": "x" })).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(api.delete(&entry, &bob).await, StatusCode::NOT_FOUND);
    assert_eq!(
        api.patch(
            &entry,
            &alice,
            json!({ "label": "PC de maman", "device_id": "987 654 321" })
        )
        .await,
        StatusCode::NO_CONTENT
    );
    let (_, list) = api.get(book, &alice).await;
    assert_eq!(
        (list[0]["label"].clone(), list[0]["device_id"].clone()),
        (json!("PC de maman"), json!("987 654 321"))
    );
    assert_eq!(api.delete(&entry, &alice).await, StatusCode::NO_CONTENT);
    assert_eq!(api.get(book, &alice).await.1, json!([]));
}
