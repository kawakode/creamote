//! Injection X11 par l'extension XTest. Code de touche X = evdev + 8 (règle
//! des serveurs utilisant le pilote evdev/libinput, universelle aujourd'hui).

use x11rb::connection::Connection;
use x11rb::protocol::xproto::{
    BUTTON_PRESS_EVENT, BUTTON_RELEASE_EVENT, KEY_PRESS_EVENT, KEY_RELEASE_EVENT,
    MOTION_NOTIFY_EVENT, Window,
};
use x11rb::protocol::xtest::ConnectionExt as _;
use x11rb::rust_connection::RustConnection;

use crate::keymap::NONE;
use crate::{Backend, Button, InputError, Key, Result, WheelAccumulator};

fn err(e: impl std::fmt::Display) -> InputError {
    InputError::Backend(format!("XTest : {e}"))
}

pub(crate) struct XTest {
    conn: RustConnection,
    root: Window,
    wheel: WheelAccumulator,
}

impl XTest {
    pub(crate) fn open() -> Result<Self> {
        let (conn, screen) = RustConnection::connect(None)
            .map_err(|e| InputError::Unsupported(format!("pas de serveur X11 : {e}")))?;
        conn.xtest_get_version(2, 2)
            .map_err(err)?
            .reply()
            .map_err(|_| InputError::Unsupported("extension XTest absente".into()))?;
        let root = conn.setup().roots[screen].root;
        Ok(Self {
            conn,
            root,
            wheel: WheelAccumulator::default(),
        })
    }

    fn fake(&self, kind: u8, detail: u8, x: i16, y: i16) -> Result<()> {
        self.conn
            .xtest_fake_input(kind, detail, x11rb::CURRENT_TIME, self.root, x, y, 0)
            .map_err(err)?;
        Ok(())
    }

    fn click(&self, button: u8, times: i32) -> Result<()> {
        for _ in 0..times {
            self.fake(BUTTON_PRESS_EVENT, button, 0, 0)?;
            self.fake(BUTTON_RELEASE_EVENT, button, 0, 0)?;
        }
        Ok(())
    }
}

impl Backend for XTest {
    fn key(&mut self, key: &Key, pressed: bool) -> Result<()> {
        if key.evdev == NONE || key.evdev > 247 {
            return Ok(());
        }
        let kind = if pressed {
            KEY_PRESS_EVENT
        } else {
            KEY_RELEASE_EVENT
        };
        self.fake(kind, (key.evdev + 8) as u8, 0, 0)
    }

    fn move_to(&mut self, x: f64, y: f64, _buttons: u32) -> Result<()> {
        self.fake(MOTION_NOTIFY_EVENT, 0, x as i16, y as i16)
    }

    fn button(&mut self, button: Button, pressed: bool, _x: f64, _y: f64) -> Result<()> {
        let detail = match button {
            Button::Left => 1,
            Button::Middle => 2,
            Button::Right => 3,
            Button::Back => 8,
            Button::Forward => 9,
        };
        let kind = if pressed {
            BUTTON_PRESS_EVENT
        } else {
            BUTTON_RELEASE_EVENT
        };
        self.fake(kind, detail, 0, 0)
    }

    fn scroll(&mut self, dx: f32, dy: f32) -> Result<()> {
        let (ix, iy) = self.wheel.add(dx, dy);
        // Boutons 4/5 : haut/bas ; 6/7 : gauche/droite.
        self.click(if iy > 0 { 5 } else { 4 }, iy.abs())?;
        self.click(if ix > 0 { 7 } else { 6 }, ix.abs())
    }

    fn flush(&mut self) -> Result<()> {
        self.conn.flush().map_err(err)
    }
}
