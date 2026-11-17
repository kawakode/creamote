//! OS sans capture native depuis Rust. Sur Android, l'écran est capturé et
//! encodé par l'app (MediaProjection + MediaCodec), qui fournit ses propres
//! sources au host (`creamote-mobile`).

use crate::{CaptureError, Capturer, DisplayInfo, Result};

pub fn init() {}

fn unsupported() -> CaptureError {
    CaptureError::Unsupported(format!(
        "pas de capture native sur {}",
        std::env::consts::OS
    ))
}

pub fn displays() -> Result<Vec<DisplayInfo>> {
    Err(unsupported())
}

pub fn open(_display: DisplayInfo) -> Result<Box<dyn Capturer>> {
    Err(unsupported())
}
