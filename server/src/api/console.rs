//! Console web d'administration : application monopage sans dépendance,
//! embarquée dans le binaire et servie par l'API (même origine).
//!
//! Les fichiers sont dans `server/console/`. La console ne contient aucun
//! script tiers ; la politique de sécurité du contenu n'autorise que les
//! ressources de la même origine.

use axum::Router;
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use super::AppState;

const INDEX: &str = include_str!("../../console/index.html");
const APP_JS: &str = include_str!("../../console/app.js");
const APP_CSS: &str = include_str!("../../console/app.css");
const ICON: &str = include_str!("../../console/icon.svg");

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
    img-src 'self' blob:; connect-src 'self'; base-uri 'none'; form-action 'none'; \
    frame-ancestors 'none'";

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/",
            get(|| async { file("text/html; charset=utf-8", INDEX) }),
        )
        .route(
            "/app.js",
            get(|| async { file("text/javascript; charset=utf-8", APP_JS) }),
        )
        .route(
            "/app.css",
            get(|| async { file("text/css; charset=utf-8", APP_CSS) }),
        )
        .route("/icon.svg", get(|| async { file("image/svg+xml", ICON) }))
}

fn file(content_type: &'static str, body: &'static str) -> Response {
    let mut resp = body.into_response();
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    // La console change avec le binaire : on revalide à chaque chargement.
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    resp
}
