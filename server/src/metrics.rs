//! Compteurs du serveur, exposés au format texte de Prometheus
//! (`--metrics-listen`). Aucune donnée personnelle : ni ID, ni adresse.

use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};

macro_rules! metrics {
    ($( $field:ident : $kind:literal, $help:literal; )*) => {
        #[derive(Default)]
        pub struct Metrics {
            $( pub $field: AtomicU64, )*
        }

        impl Metrics {
            fn render_counters(&self, out: &mut String) {
                $(
                    let name = concat!("creamote_", stringify!($field));
                    let _ = writeln!(out, "# HELP {name} {}", $help);
                    let _ = writeln!(out, "# TYPE {name} {}", $kind);
                    let _ = writeln!(out, "{name} {}", self.$field.load(Ordering::Relaxed));
                )*
            }
        }
    };
}

metrics! {
    connections_total: "counter", "Connexions QUIC entrantes acceptées.";
    connections_refused_total: "counter", "Connexions refusées (trop de connexions de la même adresse).";
    connections_active: "gauge", "Connexions QUIC ouvertes.";
    registrations_total: "counter", "Enregistrements de pairs réussis.";
    registrations_rate_limited_total: "counter", "Enregistrements refusés par la limite par adresse.";
    connect_requests_total: "counter", "Demandes de session reçues.";
    connect_requests_rate_limited_total: "counter", "Demandes de session refusées par la limite par adresse.";
    sessions_declined_total: "counter", "Demandes de session refusées par le host.";
    sessions_target_offline_total: "counter", "Demandes de session vers un ID absent.";
    sessions_direct_only_total: "counter", "Sessions accordées sans relay (quota atteint), en direct seulement.";
    relay_quota_exceeded_total: "counter", "Sessions relay refusées : quota de l'adresse atteint.";
    relay_full_total: "counter", "Sessions relay refusées : relay plein.";
    relay_sessions_total: "counter", "Sessions relay ouvertes (les deux pairs présents).";
    relay_sessions_active: "gauge", "Sessions relay en cours.";
    relay_sessions_expired_total: "counter", "Sessions relay coupées à la durée maximale.";
    relay_bytes_total: "counter", "Octets recopiés par le relay (deux sens).";
}

impl Metrics {
    pub fn inc(c: &AtomicU64) {
        c.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec(c: &AtomicU64) {
        c.fetch_sub(1, Ordering::Relaxed);
    }

    /// Texte Prometheus ; `peers_online` est lu à part (taille de la table
    /// des pairs).
    pub fn render(&self, peers_online: usize) -> String {
        let mut out = String::new();
        self.render_counters(&mut out);
        let _ = writeln!(
            out,
            "# HELP creamote_peers_online Pairs enregistrés en ce moment.\n\
             # TYPE creamote_peers_online gauge\n\
             creamote_peers_online {peers_online}"
        );
        let _ = writeln!(
            out,
            "# HELP creamote_build_info Version du serveur.\n\
             # TYPE creamote_build_info gauge\n\
             creamote_build_info{{version=\"{}\"}} 1",
            env!("CARGO_PKG_VERSION")
        );
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_prometheus_text() {
        let m = Metrics::default();
        Metrics::inc(&m.relay_sessions_total);
        m.relay_bytes_total.fetch_add(42, Ordering::Relaxed);
        let text = m.render(3);
        assert!(text.contains("# TYPE creamote_relay_sessions_total counter\n"));
        assert!(text.contains("\ncreamote_relay_sessions_total 1\n"));
        assert!(text.contains("\ncreamote_relay_bytes_total 42\n"));
        assert!(text.contains("\ncreamote_peers_online 3\n"));
        assert!(text.contains("# TYPE creamote_relay_sessions_active gauge\n"));
    }
}
