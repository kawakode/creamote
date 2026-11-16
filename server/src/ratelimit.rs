//! Limites par adresse IP du serveur public : connexions simultanées,
//! enregistrements et demandes de session par minute.
//!
//! Une adresse IPv6 est comptée par préfixe /64 (le bloc qu'un opérateur
//! attribue à un seul abonné) : sinon un client changerait d'adresse à
//! chaque tentative.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Clé de comptage d'une adresse : IPv4 telle quelle (y compris IPv4 mappée
/// en IPv6), IPv6 réduite à son préfixe /64.
pub fn ip_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        },
    }
}

/// Nombre maximal d'adresses suivies, pour borner la mémoire.
const MAX_KEYS: usize = 200_000;

/// Fenêtre glissante : au plus `max` événements par adresse et par
/// `window`. `max == 0` désactive la limite.
pub struct WindowLimiter {
    max: u32,
    window: Duration,
    book: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
}

impl WindowLimiter {
    pub fn new(max: u32, window: Duration) -> Self {
        Self {
            max,
            window,
            book: Mutex::default(),
        }
    }

    /// Compte un événement de `ip` ; `false` si la limite est atteinte
    /// (l'événement refusé n'est pas compté).
    pub fn allow(&self, ip: IpAddr) -> bool {
        self.allow_at(ip, Instant::now())
    }

    fn allow_at(&self, ip: IpAddr, now: Instant) -> bool {
        if self.max == 0 {
            return true;
        }
        let w = self.window;
        let fresh = |q: &mut VecDeque<Instant>| {
            while q.front().is_some_and(|t| now.duration_since(*t) >= w) {
                q.pop_front();
            }
        };
        let mut book = self.book.lock().expect("verrou sain");
        if book.len() >= MAX_KEYS {
            book.retain(|_, q| {
                fresh(q);
                !q.is_empty()
            });
            if book.len() >= MAX_KEYS {
                // Saturé par une attaque distribuée : on refuse les nouvelles
                // adresses plutôt que d'oublier les limites des autres.
                return false;
            }
        }
        let q = book.entry(ip_key(ip)).or_default();
        fresh(q);
        if q.len() >= self.max as usize {
            return false;
        }
        q.push_back(now);
        true
    }
}

/// Compteur d'éléments simultanés par adresse (connexions, sessions relay).
#[derive(Clone, Default)]
pub struct IpCounts(Arc<Mutex<HashMap<IpAddr, u32>>>);

/// L'adresse occupe déjà toutes ses places.
#[derive(Debug)]
pub struct LimitReached;

/// Place occupée, rendue quand le garde est détruit.
pub struct IpGuard {
    counts: IpCounts,
    key: IpAddr,
}

impl IpCounts {
    /// Réserve une place pour `ip` ; `None` si elle en occupe déjà `max`.
    /// `max == 0` : pas de limite (et pas de garde).
    pub fn acquire(&self, ip: IpAddr, max: u32) -> Result<Option<IpGuard>, LimitReached> {
        if max == 0 {
            return Ok(None);
        }
        let key = ip_key(ip);
        let mut map = self.0.lock().expect("verrou sain");
        let n = map.entry(key).or_insert(0);
        if *n >= max {
            return Err(LimitReached);
        }
        *n += 1;
        Ok(Some(IpGuard {
            counts: self.clone(),
            key,
        }))
    }
}

impl Drop for IpGuard {
    fn drop(&mut self) {
        let mut map = self.counts.0.lock().expect("verrou sain");
        if let Some(n) = map.get_mut(&self.key) {
            *n -= 1;
            if *n == 0 {
                map.remove(&self.key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_counts_per_64_prefix() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:bbbb::9".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(ip_key(a), ip_key(b));
        assert_ne!(ip_key(a), ip_key(c));
        let mapped: IpAddr = "::ffff:192.0.2.7".parse().unwrap();
        assert_eq!(ip_key(mapped), "192.0.2.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn window_limits_then_forgets() {
        let l = WindowLimiter::new(2, Duration::from_secs(60));
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let t0 = Instant::now();
        assert!(l.allow_at(ip, t0));
        assert!(l.allow_at(ip, t0));
        assert!(!l.allow_at(ip, t0 + Duration::from_secs(1)));
        assert!(l.allow_at("192.0.2.2".parse().unwrap(), t0));
        assert!(l.allow_at(ip, t0 + Duration::from_secs(60)));
        assert!(WindowLimiter::new(0, Duration::from_secs(1)).allow(ip));
    }

    #[test]
    fn counts_release_on_drop() {
        let counts = IpCounts::default();
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let other: IpAddr = "2001:db8::2".parse().unwrap();
        let g = counts.acquire(ip, 1).unwrap();
        assert!(counts.acquire(other, 1).is_err(), "même /64");
        drop(g);
        assert!(counts.acquire(other, 1).unwrap().is_some());
        assert!(counts.acquire(ip, 0).unwrap().is_none());
    }
}
