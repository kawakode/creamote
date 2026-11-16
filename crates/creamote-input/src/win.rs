//! Injection Windows par `SendInput`. Les touches sont envoyées en scancodes
//! (position physique, indépendante de la disposition), la souris en
//! coordonnées absolues sur le bureau virtuel.
#![allow(unsafe_code)]

use windows::Win32::UI::Input::KeyboardAndMouse::{
    INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBD_EVENT_FLAGS, KEYBDINPUT,
    KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE, MOUSE_EVENT_FLAGS,
    MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_HWHEEL, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP,
    MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN,
    MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_VIRTUALDESK, MOUSEEVENTF_WHEEL, MOUSEEVENTF_XDOWN,
    MOUSEEVENTF_XUP, MOUSEINPUT, SendInput as send_input, VIRTUAL_KEY, VK_PAUSE,
};
use windows::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
    WHEEL_DELTA, XBUTTON1, XBUTTON2,
};

use crate::keymap::{NONE, PAUSE};
use crate::{Backend, Button, Key, Result};

pub(crate) struct SendInput;

impl SendInput {
    pub(crate) fn open() -> Self {
        Self
    }
}

fn send(input: INPUT) -> Result<()> {
    // SAFETY : tableau d'un INPUT initialisé, taille exacte.
    let n = unsafe { send_input(&[input], std::mem::size_of::<INPUT>() as i32) };
    if n == 0 {
        // Bloqué par l'UIPI (fenêtre élevée au premier plan) ou bureau
        // sécurisé : on journalise sans couper la session.
        tracing::debug!("SendInput refusé : {}", windows::core::Error::from_thread());
    }
    Ok(())
}

fn mouse(flags: MOUSE_EVENT_FLAGS, dx: i32, dy: i32, data: i32) -> Result<()> {
    send(INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx,
                dy,
                mouseData: data as u32,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    })
}

impl Backend for SendInput {
    fn key(&mut self, key: &Key, pressed: bool) -> Result<()> {
        let up = if pressed {
            KEYBD_EVENT_FLAGS(0)
        } else {
            KEYEVENTF_KEYUP
        };
        let ki = match key.set1 {
            NONE => return Ok(()),
            PAUSE => KEYBDINPUT {
                wVk: VK_PAUSE,
                wScan: 0,
                dwFlags: up,
                time: 0,
                dwExtraInfo: 0,
            },
            sc => {
                let mut flags = KEYEVENTF_SCANCODE | up;
                if sc & 0xFF00 == 0xE000 {
                    flags |= KEYEVENTF_EXTENDEDKEY;
                }
                KEYBDINPUT {
                    wVk: VIRTUAL_KEY(0),
                    wScan: sc & 0xFF,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                }
            }
        };
        send(INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 { ki },
        })
    }

    fn move_to(&mut self, x: f64, y: f64, _buttons: u32) -> Result<()> {
        // SAFETY : appels sans pointeur.
        let (vx, vy, vw, vh) = unsafe {
            (
                GetSystemMetrics(SM_XVIRTUALSCREEN),
                GetSystemMetrics(SM_YVIRTUALSCREEN),
                GetSystemMetrics(SM_CXVIRTUALSCREEN).max(2),
                GetSystemMetrics(SM_CYVIRTUALSCREEN).max(2),
            )
        };
        // Coordonnées absolues normalisées 0..65535 sur le bureau virtuel.
        let nx = ((x - f64::from(vx)) * 65535.0 / f64::from(vw - 1)).round() as i32;
        let ny = ((y - f64::from(vy)) * 65535.0 / f64::from(vh - 1)).round() as i32;
        mouse(
            MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
            nx,
            ny,
            0,
        )
    }

    fn button(&mut self, button: Button, pressed: bool, _x: f64, _y: f64) -> Result<()> {
        let (flags, data) = match (button, pressed) {
            (Button::Left, true) => (MOUSEEVENTF_LEFTDOWN, 0),
            (Button::Left, false) => (MOUSEEVENTF_LEFTUP, 0),
            (Button::Right, true) => (MOUSEEVENTF_RIGHTDOWN, 0),
            (Button::Right, false) => (MOUSEEVENTF_RIGHTUP, 0),
            (Button::Middle, true) => (MOUSEEVENTF_MIDDLEDOWN, 0),
            (Button::Middle, false) => (MOUSEEVENTF_MIDDLEUP, 0),
            (Button::Back, true) => (MOUSEEVENTF_XDOWN, XBUTTON1),
            (Button::Back, false) => (MOUSEEVENTF_XUP, XBUTTON1),
            (Button::Forward, true) => (MOUSEEVENTF_XDOWN, XBUTTON2),
            (Button::Forward, false) => (MOUSEEVENTF_XUP, XBUTTON2),
        };
        mouse(flags, 0, 0, i32::from(data))
    }

    fn scroll(&mut self, dx: f32, dy: f32) -> Result<()> {
        // Windows accepte des fractions de cran (WHEEL_DELTA = 120).
        let delta = WHEEL_DELTA as f32;
        if dy != 0.0 {
            // Windows : positif = molette vers l'avant (contenu vers le haut).
            mouse(MOUSEEVENTF_WHEEL, 0, 0, (-dy * delta).round() as i32)?;
        }
        if dx != 0.0 {
            mouse(MOUSEEVENTF_HWHEEL, 0, 0, (dx * delta).round() as i32)?;
        }
        Ok(())
    }
}
