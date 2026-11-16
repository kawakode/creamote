//! Wayland : le compositeur n'autorise ni capture ni injection directes.
//! Tout passe par xdg-desktop-portal (`RemoteDesktop` + `ScreenCast`) :
//! l'utilisateur choisit les écrans partagés une fois, puis l'image arrive
//! par PipeWire et les entrées repartent par le portail.

mod portal;
mod pw;

pub use portal::{KEYBOARD, POINTER, PortalSession, Stream, session};

use crate::{Capturer, DisplayInfo, Result};

/// Session Wayland détectée (ou forcée par `CREAMOTE_LINUX_BACKEND`,
/// `portal` ou `x11`).
pub fn active() -> bool {
    match std::env::var("CREAMOTE_LINUX_BACKEND").as_deref() {
        Ok("portal") => return true,
        Ok("x11") => return false,
        _ => {}
    }
    std::env::var("XDG_SESSION_TYPE").is_ok_and(|t| t == "wayland")
        || std::env::var_os("WAYLAND_DISPLAY").is_some_and(|d| !d.is_empty())
}

/// Écrans partagés par le portail ; l'identifiant est le nœud PipeWire.
pub fn displays() -> Result<Vec<DisplayInfo>> {
    let s = session()?;
    Ok(s.streams()
        .iter()
        .enumerate()
        .map(|(i, st)| DisplayInfo {
            id: st.node_id,
            name: format!("Écran {}", i + 1),
            x: st.x,
            y: st.y,
            width: st.width,
            height: st.height,
            scale: 1.0,
            primary: i == 0,
        })
        .collect())
}

pub fn open(display: DisplayInfo) -> Result<Box<dyn Capturer>> {
    Ok(Box::new(pw::PwCapturer::open(session()?, display)?))
}
