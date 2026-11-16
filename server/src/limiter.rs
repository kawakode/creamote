//! Limitation des tentatives de connexion, en mémoire.
//!
//! Deux compteurs d'échecs sur une fenêtre glissante : par compte (contre la
//! recherche d'un mot de passe ou d'un code TOTP précis) et par adresse IP
//! (contre l'essai d'un mot de passe courant sur beaucoup de comptes). Une
//! connexion réussie remet à zéro le compteur du compte.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Limits {
    pub window: Duration,
    pub per_account: usize,
    pub per_ip: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(15 * 60),
            per_account: 5,
            per_ip: 30,
        }
    }
}

/// Nombre maximal de clés suivies, pour borner la mémoire.
const MAX_KEYS: usize = 100_000;

#[derive(Default)]
struct Book {
    accounts: HashMap<String, VecDeque<Instant>>,
    ips: HashMap<IpAddr, VecDeque<Instant>>,
}

pub struct LoginLimiter {
    limits: Limits,
    book: Mutex<Book>,
}

fn prune(q: &mut VecDeque<Instant>, now: Instant, window: Duration) {
    while q.front().is_some_and(|t| now.duration_since(*t) >= window) {
        q.pop_front();
    }
}

/// Délai avant que la plus ancienne tentative sorte de la fenêtre.
fn retry_after(q: &VecDeque<Instant>, now: Instant, window: Duration) -> Duration {
    q.front()
        .map(|t| window.saturating_sub(now.duration_since(*t)))
        .unwrap_or_default()
}

impl LoginLimiter {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            book: Mutex::default(),
        }
    }

    /// `Err(délai)` si la tentative doit être refusée sans même vérifier le
    /// mot de passe.
    pub fn check(&self, account: &str, ip: Option<IpAddr>) -> Result<(), Duration> {
        let now = Instant::now();
        let w = self.limits.window;
        let mut book = self.book.lock().expect("verrou sain");
        let mut wait = Duration::ZERO;
        if let Some(q) = book.accounts.get_mut(account) {
            prune(q, now, w);
            if q.len() >= self.limits.per_account {
                wait = wait.max(retry_after(q, now, w));
            }
        }
        if let Some(q) = ip.and_then(|ip| book.ips.get_mut(&ip)) {
            prune(q, now, w);
            if q.len() >= self.limits.per_ip {
                wait = wait.max(retry_after(q, now, w));
            }
        }
        if wait.is_zero() { Ok(()) } else { Err(wait) }
    }

    pub fn failure(&self, account: &str, ip: Option<IpAddr>) {
        let now = Instant::now();
        let w = self.limits.window;
        let mut book = self.book.lock().expect("verrou sain");
        if book.accounts.len() + book.ips.len() >= MAX_KEYS {
            book.accounts.retain(|_, q| {
                prune(q, now, w);
                !q.is_empty()
            });
            book.ips.retain(|_, q| {
                prune(q, now, w);
                !q.is_empty()
            });
        }
        if book.accounts.len() < MAX_KEYS {
            book.accounts
                .entry(account.to_owned())
                .or_default()
                .push_back(now);
        }
        if let Some(ip) = ip
            && book.ips.len() < MAX_KEYS
        {
            book.ips.entry(ip).or_default().push_back(now);
        }
    }

    pub fn success(&self, account: &str) {
        self.book
            .lock()
            .expect("verrou sain")
            .accounts
            .remove(account);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter() -> LoginLimiter {
        LoginLimiter::new(Limits {
            window: Duration::from_secs(60),
            per_account: 3,
            per_ip: 5,
        })
    }

    #[test]
    fn locks_account_after_failures_and_resets_on_success() {
        let l = limiter();
        let ip = Some("10.0.0.1".parse().unwrap());
        for _ in 0..3 {
            assert!(l.check("a", ip).is_ok());
            l.failure("a", ip);
        }
        let wait = l.check("a", ip).unwrap_err();
        assert!(wait <= Duration::from_secs(60) && wait > Duration::from_secs(55));
        assert!(l.check("b", ip).is_ok(), "autre compte");
        l.success("a");
        assert!(l.check("a", ip).is_ok());
    }

    #[test]
    fn locks_ip_across_accounts() {
        let l = limiter();
        let ip = Some("10.0.0.2".parse().unwrap());
        for i in 0..5 {
            l.failure(&format!("u{i}"), ip);
        }
        assert!(l.check("nouveau", ip).is_err());
        assert!(
            l.check("nouveau", Some("10.0.0.3".parse().unwrap()))
                .is_ok()
        );
        assert!(l.check("nouveau", None).is_ok());
    }
}
