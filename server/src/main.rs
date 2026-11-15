//! Serveur Creamote.
//!
//! M0 : squelette seulement. Le rendezvous et le relay arrivent en M1, l'API
//! de gestion (comptes, entités, parcs, RBAC) en M4.

fn main() {
    let v = creamote_proto::PROTOCOL_VERSION;
    println!(
        "creamote-server {} (protocole {}.{}.{}) : rendezvous et relay prévus au milestone M1",
        env!("CARGO_PKG_VERSION"),
        v.major,
        v.minor,
        v.patch
    );
}
