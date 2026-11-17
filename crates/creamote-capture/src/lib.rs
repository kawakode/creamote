//! Capture d'écran par les API natives de chaque OS.
//!
//! | OS | API | Notes |
//! | --- | --- | --- |
//! | Windows | DXGI Desktop Duplication | images livrées seulement quand l'écran change |
//! | macOS | ScreenCaptureKit (12.3+) | curseur inclus, autorisation « Enregistrement de l'écran » |
//! | Linux X11 | MIT-SHM (repli `GetImage`), XFixes pour le curseur | |
//! | Linux Wayland | portail `RemoteDesktop`/`ScreenCast` + PipeWire | boîte du portail, puis jeton de restauration |
//! | Android | MediaProjection, dans l'app Kotlin (`android/`) | ce crate renvoie `Unsupported` |
//!
//! Les images sont livrées en BGRA 8 bits en mémoire, prêtes pour
//! l'encodeur. Le zéro-copie GPU → encodeur viendra avec le débit adaptatif.

use std::time::{Duration, Instant};

#[cfg(windows)]
mod dxgi;
#[cfg(target_os = "macos")]
mod sck;
#[cfg(all(target_os = "linux", feature = "wayland"))]
pub mod wayland;
#[cfg(target_os = "linux")]
mod x11;

#[cfg(windows)]
use dxgi as platform;
#[cfg(target_os = "macos")]
use sck as platform;
#[cfg(target_os = "linux")]
use x11 as platform;
// Android (MediaProjection, côté Kotlin) et autres OS : pas de capture native
// depuis Rust ; l'app fournit ses propres sources au host.
#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
mod unsupported;
#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
use unsupported as platform;

#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("aucun écran trouvé")]
    NoDisplay,
    #[error("écran inconnu : {0}")]
    UnknownDisplay(u32),
    #[error("autorisation de capture d'écran refusée{0}")]
    PermissionDenied(&'static str),
    #[error("capture d'écran non prise en charge : {0}")]
    Unsupported(String),
    #[error("API de capture : {0}")]
    Backend(String),
}

pub type Result<T, E = CaptureError> = std::result::Result<T, E>;

/// Écran capturable. Les coordonnées sont en pixels physiques sur le bureau
/// virtuel (Windows, X11) ou en points (macOS, voir `scale`).
#[derive(Debug, Clone, PartialEq)]
pub struct DisplayInfo {
    /// Identifiant stable pendant la vie du processus.
    pub id: u32,
    pub name: String,
    pub x: i32,
    pub y: i32,
    /// Taille de l'image capturée, en pixels.
    pub width: u32,
    pub height: u32,
    /// Pixels par unité de coordonnées du bureau (2.0 sur un écran Retina).
    pub scale: f32,
    pub primary: bool,
}

/// Image capturée, BGRA 8 bits, lignes de `stride` octets.
#[derive(Clone)]
pub struct Frame {
    pub width: u32,
    pub height: u32,
    pub stride: usize,
    pub data: Vec<u8>,
    pub captured_at: Instant,
}

impl Frame {
    /// Image unie, pour les tests et les sources synthétiques.
    pub fn solid(width: u32, height: u32, bgra: [u8; 4]) -> Self {
        let data = bgra
            .iter()
            .copied()
            .cycle()
            .take(width as usize * height as usize * 4)
            .collect();
        Self {
            width,
            height,
            stride: width as usize * 4,
            data,
            captured_at: Instant::now(),
        }
    }

    /// Ligne `y` (sans le remplissage éventuel).
    pub fn row(&self, y: usize) -> &[u8] {
        let start = y * self.stride;
        &self.data[start..start + self.width as usize * 4]
    }
}

impl std::fmt::Debug for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Frame")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("stride", &self.stride)
            .finish_non_exhaustive()
    }
}

/// Source d'images d'un écran. Une instance appartient à un seul thread
/// (objets COM ou connexions natives) : créez-la dans le thread de capture.
pub trait Capturer {
    fn display(&self) -> &DisplayInfo;

    /// Attend la prochaine image **différente** de la précédente, au plus
    /// `timeout`. `Ok(None)` : l'écran n'a pas changé.
    fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame>>;
}

/// Prépare le processus pour la capture et l'injection (Windows : prise en
/// compte du DPI par écran, sans quoi les coordonnées sont mises à l'échelle).
/// Idempotent ; à appeler au démarrage.
pub fn init() {
    platform::init();
}

/// Écrans disponibles, l'écran principal en premier.
pub fn displays() -> Result<Vec<DisplayInfo>> {
    #[cfg(all(target_os = "linux", feature = "wayland"))]
    if wayland::active() {
        return wayland::displays();
    }
    let mut d = platform::displays()?;
    d.sort_by_key(|d| !d.primary);
    Ok(d)
}

/// Ouvre la capture d'un écran (`None` : l'écran principal).
pub fn open(display_id: Option<u32>) -> Result<Box<dyn Capturer>> {
    let displays = displays()?;
    let display = match display_id {
        None => displays.into_iter().next().ok_or(CaptureError::NoDisplay)?,
        Some(id) => displays
            .into_iter()
            .find(|d| d.id == id)
            .ok_or(CaptureError::UnknownDisplay(id))?,
    };
    #[cfg(all(target_os = "linux", feature = "wayland"))]
    if wayland::active() {
        return wayland::open(display);
    }
    platform::open(display)
}

/// Copie `height` lignes de `width * 4` octets depuis un tampon de pas
/// `src_stride` vers un tampon compact.
#[cfg_attr(not(any(windows, target_os = "macos")), allow(dead_code))]
pub(crate) fn copy_rows(src: &[u8], src_stride: usize, width: u32, height: u32) -> Vec<u8> {
    let row = width as usize * 4;
    let mut out = Vec::with_capacity(row * height as usize);
    for y in 0..height as usize {
        out.extend_from_slice(&src[y * src_stride..y * src_stride + row]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_rows_drops_padding() {
        let src = [1, 1, 1, 1, 9, 9, 2, 2, 2, 2, 9, 9];
        assert_eq!(copy_rows(&src, 6, 1, 2), [1, 1, 1, 1, 2, 2, 2, 2]);
    }

    #[test]
    fn solid_frame_layout() {
        let f = Frame::solid(3, 2, [1, 2, 3, 4]);
        assert_eq!(f.data.len(), 24);
        assert_eq!(f.row(1), &[1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4]);
    }

    /// Ne doit jamais paniquer, même sans écran (CI).
    #[test]
    fn displays_does_not_panic() {
        init();
        let _ = displays();
    }
}
