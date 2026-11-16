//! Débit adaptatif côté host.
//!
//! Le viewer accuse réception de chaque image décodée ; le délai entre
//! l'envoi d'une image et son accusé mesure la file d'attente sur le chemin
//! (réseau, relay, décodage). Quand ce délai monte nettement au-dessus du
//! minimum observé, le lien sature : le débit baisse (×0,75). Quand il reste
//! bas et que l'encodeur utilise vraiment le débit alloué, il remonte
//! (×1,1) jusqu'au plafond. Les changements sont espacés, car certains
//! encodeurs (openh264) repartent d'une image clé à chaque changement.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Débit plancher.
pub const MIN_BITRATE: u32 = 300_000;
/// File d'attente au-delà de laquelle le lien est considéré saturé.
const CONGESTED: Duration = Duration::from_millis(80);
/// File d'attente sous laquelle le lien est considéré libre.
const CLEAR: Duration = Duration::from_millis(25);
/// Fenêtre de mesure du délai minimal (le chemin peut changer).
const BASE_WINDOW: Duration = Duration::from_secs(10);
const DECREASE_EVERY: Duration = Duration::from_secs(1);
const INCREASE_AFTER: Duration = Duration::from_secs(3);
/// Fenêtre de mesure du débit réellement produit.
const USAGE_WINDOW: Duration = Duration::from_secs(2);
/// Images envoyées dont on attend encore l'accusé (au-delà, oubliées).
const MAX_TRACKED: usize = 64;

pub struct RateController {
    max: u32,
    current: u32,
    sent: VecDeque<(u64, Instant, usize)>,
    /// (instant, octets) des images envoyées récemment.
    usage: VecDeque<(Instant, usize)>,
    base: Option<(Duration, Instant)>,
    smoothed: Option<Duration>,
    last_change: Instant,
    clear_since: Option<Instant>,
}

impl RateController {
    /// `max` : débit de départ et plafond (celui demandé par le viewer ou
    /// choisi pour la résolution).
    pub fn new(max: u32, now: Instant) -> Self {
        let max = max.max(MIN_BITRATE);
        Self {
            max,
            current: max,
            sent: VecDeque::new(),
            usage: VecDeque::new(),
            base: None,
            smoothed: None,
            last_change: now,
            clear_since: None,
        }
    }

    pub fn bitrate(&self) -> u32 {
        self.current
    }

    /// Image `frame_id` de `bytes` octets envoyée à `at`.
    pub fn on_sent(&mut self, frame_id: u64, bytes: usize, at: Instant) {
        self.sent.push_back((frame_id, at, bytes));
        if self.sent.len() > MAX_TRACKED {
            self.sent.pop_front();
        }
        self.usage.push_back((at, bytes));
    }

    /// Accusé de réception de `frame_id` reçu à `at`.
    pub fn on_ack(&mut self, frame_id: u64, at: Instant) {
        let Some(pos) = self.sent.iter().position(|(id, ..)| *id == frame_id) else {
            return;
        };
        let (_, sent_at, _) = self.sent[pos];
        // Les images plus anciennes sont implicitement acquittées.
        self.sent.drain(..=pos);
        let delay = at.saturating_duration_since(sent_at);
        self.base = match self.base {
            Some((b, since)) if delay >= b && at.duration_since(since) < BASE_WINDOW => {
                Some((b, since))
            }
            _ => Some((delay, at)),
        };
        // Moyenne exponentielle (1/4) : réagit en quelques images.
        self.smoothed = Some(match self.smoothed {
            Some(s) => (s * 3 + delay) / 4,
            None => delay,
        });
    }

    /// Nouveau débit à appliquer, s'il change.
    pub fn tick(&mut self, now: Instant) -> Option<u32> {
        while self
            .usage
            .front()
            .is_some_and(|(t, _)| now.duration_since(*t) > USAGE_WINDOW)
        {
            self.usage.pop_front();
        }
        let (Some((base, _)), Some(smoothed)) = (self.base, self.smoothed) else {
            return None;
        };
        let queue = smoothed.saturating_sub(base);
        if queue > CONGESTED {
            self.clear_since = None;
            if now.duration_since(self.last_change) >= DECREASE_EVERY && self.current > MIN_BITRATE
            {
                return self.set((self.current as u64 * 3 / 4) as u32, now);
            }
            return None;
        }
        if queue > CLEAR {
            self.clear_since = None;
            return None;
        }
        let since = *self.clear_since.get_or_insert(now);
        let produced: usize = self.usage.iter().map(|(_, b)| b).sum();
        let used = produced as f64 * 8.0 / USAGE_WINDOW.as_secs_f64();
        // Écran presque fixe : l'encodeur n'utilise pas le débit, inutile de
        // l'augmenter.
        let busy = used >= f64::from(self.current) * 0.5;
        if self.current < self.max
            && busy
            && now.duration_since(since) >= INCREASE_AFTER
            && now.duration_since(self.last_change) >= INCREASE_AFTER
        {
            let next = (self.current as u64 * 11 / 10) as u32;
            self.clear_since = Some(now);
            return self.set(next, now);
        }
        None
    }

    fn set(&mut self, bps: u32, now: Instant) -> Option<u32> {
        let bps = bps.clamp(MIN_BITRATE, self.max);
        self.last_change = now;
        // La file mesurée appartient à l'ancien débit.
        self.smoothed = None;
        if bps == self.current {
            return None;
        }
        self.current = bps;
        Some(bps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Simule `secs` secondes à 30 i/s avec un délai d'accusé donné.
    fn run(
        rc: &mut RateController,
        t: &mut Instant,
        next_id: &mut u64,
        secs: u32,
        bytes: usize,
        delay: impl Fn(u64) -> Duration,
    ) -> Vec<u32> {
        let mut changes = Vec::new();
        for _ in 0..secs * 30 {
            *next_id += 1;
            rc.on_sent(*next_id, bytes, *t);
            rc.on_ack(*next_id, *t + delay(*next_id));
            *t += Duration::from_millis(33);
            if let Some(b) = rc.tick(*t) {
                changes.push(b);
            }
        }
        changes
    }

    #[test]
    fn backs_off_under_congestion_and_recovers() {
        let start = Instant::now();
        let mut t = start;
        let mut id = 0;
        let mut rc = RateController::new(8_000_000, start);
        // 8 Mbit/s ≈ 33 Kio par image à 30 i/s.
        let full = 33_000;
        let quiet = run(&mut rc, &mut t, &mut id, 3, full, |_| {
            Duration::from_millis(20)
        });
        assert!(quiet.is_empty(), "pas de changement sans saturation");

        // La file grimpe : baisses successives, espacées d'au moins 1 s.
        let down = run(&mut rc, &mut t, &mut id, 4, full, |_| {
            Duration::from_millis(250)
        });
        assert!(down.len() >= 2 && down.len() <= 4, "{down:?}");
        assert!(down.windows(2).all(|w| w[1] < w[0]));
        let low = *down.last().unwrap();
        assert!(low <= 4_500_000);

        // Le lien se libère : remontée progressive jusqu'au plafond.
        let up = run(&mut rc, &mut t, &mut id, 60, full, |_| {
            Duration::from_millis(20)
        });
        assert!(up.windows(2).all(|w| w[1] > w[0]), "{up:?}");
        assert_eq!(rc.bitrate(), 8_000_000);
    }

    #[test]
    fn static_screen_does_not_raise_the_bitrate() {
        let start = Instant::now();
        let mut t = start;
        let mut id = 0;
        let mut rc = RateController::new(8_000_000, start);
        run(&mut rc, &mut t, &mut id, 1, 33_000, |_| {
            Duration::from_millis(20)
        });
        run(&mut rc, &mut t, &mut id, 4, 33_000, |_| {
            Duration::from_millis(300)
        });
        let low = rc.bitrate();
        assert!(low < 8_000_000);
        // Petites images (écran fixe) et lien libre : pas de hausse.
        let up = run(&mut rc, &mut t, &mut id, 20, 500, |_| {
            Duration::from_millis(20)
        });
        assert!(up.is_empty(), "{up:?}");
        assert_eq!(rc.bitrate(), low);
    }

    #[test]
    fn constant_latency_is_not_congestion() {
        let start = Instant::now();
        let mut t = start;
        let mut id = 0;
        let mut rc = RateController::new(8_000_000, start);
        // Lien lointain mais pas saturé : délai élevé et stable.
        let changes = run(&mut rc, &mut t, &mut id, 10, 33_000, |_| {
            Duration::from_millis(300)
        });
        assert!(changes.is_empty(), "{changes:?}");
    }

    #[test]
    fn never_below_floor() {
        let start = Instant::now();
        let mut t = start;
        let mut id = 0;
        let mut rc = RateController::new(1_000_000, start);
        run(&mut rc, &mut t, &mut id, 1, 4_000, |_| {
            Duration::from_millis(20)
        });
        run(&mut rc, &mut t, &mut id, 9, 4_000, |_| {
            Duration::from_millis(500)
        });
        assert_eq!(rc.bitrate(), MIN_BITRATE);
    }
}
