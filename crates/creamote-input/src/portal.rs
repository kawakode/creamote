//! Injection Wayland par le portail `RemoteDesktop`, dans la session déjà
//! ouverte pour la capture (une seule autorisation). Les positions sont
//! données en coordonnées logiques du flux de l'écran diffusé.

use std::sync::Arc;

use creamote_capture::DisplayInfo;
use creamote_capture::wayland::{KEYBOARD, POINTER, PortalSession, session};

use crate::keymap::NONE;
use crate::{Backend, Button, InputError, Key, Result, WheelAccumulator};

fn err(e: impl std::fmt::Display) -> InputError {
    InputError::Backend(format!("portail : {e}"))
}

pub(crate) struct Portal {
    session: Arc<PortalSession>,
    display: DisplayInfo,
    wheel: WheelAccumulator,
}

impl Portal {
    pub(crate) fn open(display: &DisplayInfo) -> Result<Self> {
        let session = session().map_err(|e| InputError::Unsupported(e.to_string()))?;
        if session.devices() & (KEYBOARD | POINTER) == 0 {
            return Err(InputError::PermissionDenied(
                " : clavier et souris non partagés dans la boîte du portail",
            ));
        }
        Ok(Self {
            session,
            display: display.clone(),
            wheel: WheelAccumulator::default(),
        })
    }
}

/// Codes evdev des boutons (`BTN_LEFT`…).
fn evdev_button(b: Button) -> i32 {
    match b {
        Button::Left => 0x110,
        Button::Right => 0x111,
        Button::Middle => 0x112,
        Button::Back => 0x113,
        Button::Forward => 0x114,
    }
}

impl Backend for Portal {
    fn key(&mut self, key: &Key, pressed: bool) -> Result<()> {
        if key.evdev == NONE || self.session.devices() & KEYBOARD == 0 {
            return Ok(());
        }
        self.session.key(key.evdev, pressed).map_err(err)
    }

    fn move_to(&mut self, x: f64, y: f64, _buttons: u32) -> Result<()> {
        if self.session.devices() & POINTER == 0 {
            return Ok(());
        }
        let d = &self.display;
        self.session
            .motion(d.id, x - f64::from(d.x), y - f64::from(d.y))
            .map_err(err)
    }

    fn button(&mut self, button: Button, pressed: bool, _x: f64, _y: f64) -> Result<()> {
        if self.session.devices() & POINTER == 0 {
            return Ok(());
        }
        self.session
            .button(evdev_button(button), pressed)
            .map_err(err)
    }

    fn scroll(&mut self, dx: f32, dy: f32) -> Result<()> {
        if self.session.devices() & POINTER == 0 {
            return Ok(());
        }
        let (ix, iy) = self.wheel.add(dx, dy);
        if iy != 0 {
            self.session.scroll(false, iy).map_err(err)?;
        }
        if ix != 0 {
            self.session.scroll(true, ix).map_err(err)?;
        }
        Ok(())
    }
}
