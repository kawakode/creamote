//! Injection macOS par `CGEventPost` au niveau HID. Nécessite l'autorisation
//! « Accessibilité » (Réglages Système > Confidentialité et sécurité).

use std::time::{Duration, Instant};

use objc2_core_foundation::{CFRetained, CGPoint};
use objc2_core_graphics::{
    CGEvent, CGEventField, CGEventFlags, CGEventSource, CGEventSourceStateID, CGEventTapLocation,
    CGEventType, CGMouseButton, CGPreflightPostEventAccess, CGRequestPostEventAccess,
    CGScrollEventUnit,
};

use crate::keymap::NONE;
use crate::{Backend, Button, InputError, Key, Result, WheelAccumulator};

const PERMISSION_HINT: &str = " : autorisez ce programme dans Réglages Système > Confidentialité et \
     sécurité > Accessibilité, puis relancez-le";

/// Délai et distance maximaux entre deux clics pour un double clic.
const MULTI_CLICK: Duration = Duration::from_millis(500);
const MULTI_CLICK_DIST: f64 = 4.0;

pub(crate) struct CgEvents {
    source: Option<CFRetained<CGEventSource>>,
    flags: CGEventFlags,
    wheel: WheelAccumulator,
    last_click: Option<(Button, Instant, f64, f64, i64)>,
    click_state: i64,
}

impl CgEvents {
    pub(crate) fn open() -> Result<Self> {
        if !CGPreflightPostEventAccess() {
            CGRequestPostEventAccess();
            return Err(InputError::PermissionDenied(PERMISSION_HINT));
        }
        Ok(Self {
            source: CGEventSource::new(CGEventSourceStateID::HIDSystemState),
            flags: CGEventFlags::empty(),
            wheel: WheelAccumulator::default(),
            last_click: None,
            click_state: 1,
        })
    }

    fn post(&self, event: Option<CFRetained<CGEvent>>) {
        if let Some(e) = event {
            CGEvent::post(CGEventTapLocation::HIDEventTap, Some(&e));
        }
    }
}

fn modifier(key: &Key) -> Option<CGEventFlags> {
    Some(match key.code {
        "ShiftLeft" | "ShiftRight" => CGEventFlags::MaskShift,
        "ControlLeft" | "ControlRight" => CGEventFlags::MaskControl,
        "AltLeft" | "AltRight" => CGEventFlags::MaskAlternate,
        "MetaLeft" | "MetaRight" => CGEventFlags::MaskCommand,
        _ => return None,
    })
}

impl Backend for CgEvents {
    fn key(&mut self, key: &Key, pressed: bool) -> Result<()> {
        if key.mac == NONE {
            return Ok(());
        }
        if let Some(m) = modifier(key) {
            self.flags.set(m, pressed);
        }
        let e = CGEvent::new_keyboard_event(self.source.as_deref(), key.mac, pressed);
        // Les modificateurs synthétiques ne mettent pas toujours à jour
        // l'état système : on les fixe explicitement sur chaque événement.
        CGEvent::set_flags(e.as_deref(), self.flags);
        self.post(e);
        Ok(())
    }

    fn move_to(&mut self, x: f64, y: f64, buttons: u32) -> Result<()> {
        let (kind, button) = if buttons & Button::Left.mask() != 0 {
            (CGEventType::LeftMouseDragged, CGMouseButton::Left)
        } else if buttons & Button::Right.mask() != 0 {
            (CGEventType::RightMouseDragged, CGMouseButton::Right)
        } else if buttons != 0 {
            (CGEventType::OtherMouseDragged, CGMouseButton::Center)
        } else {
            (CGEventType::MouseMoved, CGMouseButton::Left)
        };
        let e = CGEvent::new_mouse_event(self.source.as_deref(), kind, CGPoint { x, y }, button);
        CGEvent::set_flags(e.as_deref(), self.flags);
        self.post(e);
        Ok(())
    }

    fn button(&mut self, b: Button, pressed: bool, x: f64, y: f64) -> Result<()> {
        let (kind, button, number) = match (b, pressed) {
            (Button::Left, true) => (CGEventType::LeftMouseDown, CGMouseButton::Left, 0),
            (Button::Left, false) => (CGEventType::LeftMouseUp, CGMouseButton::Left, 0),
            (Button::Right, true) => (CGEventType::RightMouseDown, CGMouseButton::Right, 1),
            (Button::Right, false) => (CGEventType::RightMouseUp, CGMouseButton::Right, 1),
            (other, true) => (
                CGEventType::OtherMouseDown,
                CGMouseButton::Center,
                other_number(other),
            ),
            (other, false) => (
                CGEventType::OtherMouseUp,
                CGMouseButton::Center,
                other_number(other),
            ),
        };
        if pressed {
            // Double et triple clics : macOS les reconnaît au compteur
            // `clickState` porté par l'événement, pas au délai entre clics.
            self.click_state = match self.last_click {
                Some((lb, t, lx, ly, n))
                    if lb == b
                        && t.elapsed() < MULTI_CLICK
                        && (lx - x).abs() < MULTI_CLICK_DIST
                        && (ly - y).abs() < MULTI_CLICK_DIST =>
                {
                    n + 1
                }
                _ => 1,
            };
            self.last_click = Some((b, Instant::now(), x, y, self.click_state));
        }
        let e = CGEvent::new_mouse_event(self.source.as_deref(), kind, CGPoint { x, y }, button);
        CGEvent::set_integer_value_field(
            e.as_deref(),
            CGEventField::MouseEventClickState,
            self.click_state,
        );
        CGEvent::set_integer_value_field(
            e.as_deref(),
            CGEventField::MouseEventButtonNumber,
            number,
        );
        CGEvent::set_flags(e.as_deref(), self.flags);
        self.post(e);
        Ok(())
    }

    fn scroll(&mut self, dx: f32, dy: f32) -> Result<()> {
        let (ix, iy) = self.wheel.add(dx, dy);
        if ix == 0 && iy == 0 {
            return Ok(());
        }
        // macOS : positif = contenu vers le haut / vers la gauche.
        let e = CGEvent::new_scroll_wheel_event2(
            self.source.as_deref(),
            CGScrollEventUnit::Line,
            2,
            -iy,
            -ix,
            0,
        );
        self.post(e);
        Ok(())
    }
}

fn other_number(b: Button) -> i64 {
    match b {
        Button::Middle => 2,
        Button::Back => 3,
        Button::Forward => 4,
        Button::Left => 0,
        Button::Right => 1,
    }
}
