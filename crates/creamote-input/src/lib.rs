//! Injection clavier/souris par les API natives.
//!
//! | OS | API | Autorisation |
//! | --- | --- | --- |
//! | Windows | `SendInput` (scancodes, indépendant de la disposition) | aucune ; pas d'accès au bureau sécurisé (UAC) sans service (M6) |
//! | macOS | `CGEventPost` (codes de touche physiques) | « Accessibilité » dans Réglages Système |
//! | Linux X11 | XTest | aucune |
//!
//! Le viewer envoie des **touches physiques** (usages USB HID) : le texte
//! produit dépend de la disposition clavier du host, comme sur un clavier
//! branché localement. Les coordonnées de pointeur sont normalisées [0, 1]
//! sur l'écran capturé.

use std::collections::BTreeSet;

use creamote_capture::DisplayInfo;

mod keymap;
#[cfg(target_os = "macos")]
mod mac;
#[cfg(all(target_os = "linux", feature = "wayland"))]
mod portal;
#[cfg(windows)]
mod win;
#[cfg(target_os = "linux")]
mod xtest;

pub use keymap::{Key, by_code, by_hid};

#[derive(Debug, thiserror::Error)]
pub enum InputError {
    #[error("injection d'entrées non prise en charge : {0}")]
    Unsupported(String),
    #[error("autorisation d'injection refusée{0}")]
    PermissionDenied(&'static str),
    #[error("API d'injection : {0}")]
    Backend(String),
}

pub type Result<T, E = InputError> = std::result::Result<T, E>;

/// Boutons, comme `MouseEvent.buttons` côté navigateur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Button {
    Left,
    Right,
    Middle,
    Back,
    Forward,
}

impl Button {
    pub const ALL: [Self; 5] = [
        Self::Left,
        Self::Right,
        Self::Middle,
        Self::Back,
        Self::Forward,
    ];

    pub const fn mask(self) -> u32 {
        match self {
            Self::Left => 1,
            Self::Right => 2,
            Self::Middle => 4,
            Self::Back => 8,
            Self::Forward => 16,
        }
    }
}

/// Événement de pointeur reçu du viewer.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Pointer {
    /// Position normalisée [0, 1] sur l'écran capturé.
    pub x: f32,
    pub y: f32,
    /// Masque des boutons enfoncés ([`Button::mask`]).
    pub buttons: u32,
    /// Molette en crans ; positif : vers la droite / vers le bas.
    pub wheel_dx: f32,
    pub wheel_dy: f32,
}

/// Primitives d'un OS. Les positions sont en coordonnées du bureau de l'OS
/// (pixels sous Windows et X11, points sous macOS).
pub(crate) trait Backend {
    fn key(&mut self, key: &Key, pressed: bool) -> Result<()>;
    fn move_to(&mut self, x: f64, y: f64, buttons: u32) -> Result<()>;
    fn button(&mut self, button: Button, pressed: bool, x: f64, y: f64) -> Result<()>;
    /// Molette en crans entiers ou fractionnaires selon l'OS.
    fn scroll(&mut self, dx: f32, dy: f32) -> Result<()>;
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn native_backend(display: &DisplayInfo) -> Result<Box<dyn Backend>> {
    #[cfg(feature = "wayland")]
    if creamote_capture::wayland::active() {
        return Ok(Box::new(portal::Portal::open(display)?));
    }
    let _ = display;
    Ok(Box::new(xtest::XTest::open()?))
}

#[cfg(windows)]
fn native_backend(_display: &DisplayInfo) -> Result<Box<dyn Backend>> {
    Ok(Box::new(win::SendInput::open()))
}

#[cfg(target_os = "macos")]
fn native_backend(_display: &DisplayInfo) -> Result<Box<dyn Backend>> {
    Ok(Box::new(mac::CgEvents::open()?))
}

/// Android : l'injection passe par l'AccessibilityService de l'app
/// (`creamote-mobile`), pas par ce crate.
#[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
fn native_backend(_display: &DisplayInfo) -> Result<Box<dyn Backend>> {
    Err(InputError::Unsupported(std::env::consts::OS.into()))
}

/// Injecte les événements d'un viewer sur un écran du host, en suivant les
/// touches et boutons enfoncés pour tout relâcher en fin de session.
pub struct Injector {
    backend: Box<dyn Backend>,
    display: DisplayInfo,
    pressed: BTreeSet<u32>,
    buttons: u32,
    last: Option<(f64, f64)>,
}

impl Injector {
    /// Ouvre l'injection pour l'écran capturé `display`.
    pub fn open(display: DisplayInfo) -> Result<Self> {
        let backend = native_backend(&display)?;
        Ok(Self::with_backend(backend, display))
    }

    pub(crate) fn with_backend(backend: Box<dyn Backend>, display: DisplayInfo) -> Self {
        Self {
            backend,
            display,
            pressed: BTreeSet::new(),
            buttons: 0,
            last: None,
        }
    }

    /// Touche physique (usage HID). Les usages inconnus sont ignorés.
    pub fn key(&mut self, hid_usage: u32, pressed: bool) -> Result<()> {
        let Some(key) = by_hid(hid_usage) else {
            tracing::debug!("usage HID inconnu : {hid_usage:#x}");
            return Ok(());
        };
        // Pas de relâchement sans appui, pas d'appui répété sans relâchement
        // autre que l'autorépétition (acceptée).
        if !pressed && !self.pressed.remove(&hid_usage) {
            return Ok(());
        }
        if pressed {
            self.pressed.insert(hid_usage);
        }
        self.backend.key(key, pressed)?;
        self.backend.flush()
    }

    /// Position en coordonnées du bureau de l'OS.
    fn to_desktop(&self, nx: f32, ny: f32) -> (f64, f64) {
        let d = &self.display;
        let (nx, ny) = (f64::from(nx.clamp(0.0, 1.0)), f64::from(ny.clamp(0.0, 1.0)));
        // macOS : positions en points, taille capturée en pixels.
        let scale = if cfg!(target_os = "macos") {
            f64::from(d.scale.max(0.1))
        } else {
            1.0
        };
        let w = f64::from(d.width) / scale;
        let h = f64::from(d.height) / scale;
        (
            f64::from(d.x) + (nx * w).min(w - 1.0),
            f64::from(d.y) + (ny * h).min(h - 1.0),
        )
    }

    pub fn pointer(&mut self, p: &Pointer) -> Result<()> {
        if !(p.x.is_finite() && p.y.is_finite()) {
            return Ok(());
        }
        let (x, y) = self.to_desktop(p.x, p.y);
        if self.last != Some((x, y)) {
            self.backend.move_to(x, y, self.buttons)?;
            self.last = Some((x, y));
        }
        let buttons = p.buttons & 0x1f;
        for b in Button::ALL {
            let (was, is) = (self.buttons & b.mask() != 0, buttons & b.mask() != 0);
            if was != is {
                self.backend.button(b, is, x, y)?;
                self.buttons ^= b.mask();
            }
        }
        let (dx, dy) = (finite(p.wheel_dx), finite(p.wheel_dy));
        if dx != 0.0 || dy != 0.0 {
            self.backend
                .scroll(dx.clamp(-50.0, 50.0), dy.clamp(-50.0, 50.0))?;
        }
        self.backend.flush()
    }

    /// Relâche tout ce que le viewer a laissé enfoncé (fin de session,
    /// perte de connexion). Ne doit jamais laisser une touche bloquée.
    pub fn release_all(&mut self) {
        for hid in std::mem::take(&mut self.pressed) {
            if let Some(key) = by_hid(hid) {
                let _ = self.backend.key(key, false);
            }
        }
        let (x, y) = self.last.unwrap_or_default();
        for b in Button::ALL {
            if self.buttons & b.mask() != 0 {
                let _ = self.backend.button(b, false, x, y);
            }
        }
        self.buttons = 0;
        let _ = self.backend.flush();
    }
}

impl Drop for Injector {
    fn drop(&mut self) {
        self.release_all();
    }
}

fn finite(v: f32) -> f32 {
    if v.is_finite() { v } else { 0.0 }
}

/// Accumule des crans fractionnaires et rend les crans entiers à émettre.
#[derive(Default)]
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
pub(crate) struct WheelAccumulator(f32, f32);

#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
impl WheelAccumulator {
    pub(crate) fn add(&mut self, dx: f32, dy: f32) -> (i32, i32) {
        self.0 += dx;
        self.1 += dy;
        let (ix, iy) = (self.0.trunc(), self.1.trunc());
        self.0 -= ix;
        self.1 -= iy;
        (ix as i32, iy as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Default, Clone)]
    struct Log(Arc<Mutex<Vec<String>>>);

    impl Backend for Log {
        fn key(&mut self, key: &Key, pressed: bool) -> Result<()> {
            self.0
                .lock()
                .unwrap()
                .push(format!("key {} {pressed}", key.code));
            Ok(())
        }
        fn move_to(&mut self, x: f64, y: f64, _: u32) -> Result<()> {
            self.0.lock().unwrap().push(format!("move {x} {y}"));
            Ok(())
        }
        fn button(&mut self, b: Button, pressed: bool, _: f64, _: f64) -> Result<()> {
            self.0
                .lock()
                .unwrap()
                .push(format!("button {b:?} {pressed}"));
            Ok(())
        }
        fn scroll(&mut self, dx: f32, dy: f32) -> Result<()> {
            self.0.lock().unwrap().push(format!("scroll {dx} {dy}"));
            Ok(())
        }
    }

    fn display() -> DisplayInfo {
        DisplayInfo {
            id: 0,
            name: "test".into(),
            x: 100,
            y: 0,
            width: 1000,
            height: 500,
            scale: 1.0,
            primary: true,
        }
    }

    #[test]
    fn pointer_maps_to_display_and_diffs_buttons() {
        let log = Log::default();
        let mut inj = Injector::with_backend(Box::new(log.clone()), display());
        inj.pointer(&Pointer {
            x: 0.5,
            y: 1.0,
            buttons: 1,
            ..Default::default()
        })
        .unwrap();
        inj.pointer(&Pointer {
            x: 0.5,
            y: 1.0,
            buttons: 3,
            wheel_dy: 2.0,
            ..Default::default()
        })
        .unwrap();
        inj.release_all();
        assert_eq!(
            *log.0.lock().unwrap(),
            [
                "move 600 499",
                "button Left true",
                "button Right true",
                "scroll 0 2",
                "button Left false",
                "button Right false",
            ]
        );
    }

    #[test]
    fn keys_are_tracked_and_released() {
        let log = Log::default();
        let mut inj = Injector::with_backend(Box::new(log.clone()), display());
        inj.key(0xE1, true).unwrap(); // ShiftLeft
        inj.key(0x04, true).unwrap(); // KeyA
        inj.key(0x04, false).unwrap();
        inj.key(0x05, false).unwrap(); // jamais enfoncée : ignorée
        inj.key(0xFFFF, true).unwrap(); // inconnue : ignorée
        drop(inj);
        assert_eq!(
            *log.0.lock().unwrap(),
            [
                "key ShiftLeft true",
                "key KeyA true",
                "key KeyA false",
                "key ShiftLeft false",
            ]
        );
    }

    #[test]
    fn wheel_accumulates_fractions() {
        let mut w = WheelAccumulator::default();
        assert_eq!(w.add(0.0, 0.4), (0, 0));
        assert_eq!(w.add(0.0, 0.7), (0, 1));
        assert_eq!(w.add(-1.5, -0.2), (-1, 0));
    }
}
