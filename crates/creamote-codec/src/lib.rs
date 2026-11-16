//! Encodage H.264 pour Creamote.
//!
//! [`open_h264`] choisit dans l'ordre :
//!
//! | OS | Matériel (API native) | Repli |
//! | --- | --- | --- |
//! | Windows | Media Foundation : MFT matériels du constructeur (Intel Quick Sync, NVIDIA NVENC, AMD AMF) puis encodeur Microsoft | openh264 |
//! | macOS | VideoToolbox (encodeur matériel Apple) | openh264 |
//! | Linux | VA-API / NVENC prévus avec M3 | openh264 |
//!
//! Sortie : H.264 Annex B, sans images B (latence minimale), SPS/PPS en tête
//! de chaque image clé. Si l'encodeur choisi échoue en cours de route, la
//! [`Chain`] passe au suivant et force une image clé.

use std::time::Instant;

use creamote_capture::Frame;

pub mod annexb;
#[cfg(windows)]
mod mf;
mod software;
#[cfg(target_os = "macos")]
mod vt;
pub mod yuv;

pub use software::{DecodedFrame, H264Decoder, OpenH264Encoder};

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("aucun encodeur H.264 disponible : {0}")]
    NoEncoder(String),
    #[error("encodeur : {0}")]
    Backend(String),
}

pub type Result<T, E = CodecError> = std::result::Result<T, E>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncoderConfig {
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub bitrate_bps: u32,
    /// Images entre deux images clés ; 0 : seulement à la demande.
    pub keyframe_interval: u32,
}

impl EncoderConfig {
    /// Débit par défaut selon la taille : ~0,1 bit/pixel/image, borné.
    pub fn for_size(width: u32, height: u32, fps: u32) -> Self {
        let (width, height) = yuv::even_dims(width, height);
        let bps = (u64::from(width) * u64::from(height) * u64::from(fps) / 10)
            .clamp(1_000_000, 20_000_000) as u32;
        Self {
            width,
            height,
            fps,
            bitrate_bps: bps,
            keyframe_interval: 0,
        }
    }
}

/// Image encodée, H.264 Annex B.
#[derive(Debug, Clone)]
pub struct EncodedFrame {
    pub data: Vec<u8>,
    pub keyframe: bool,
    pub captured_at: Instant,
}

/// Encodeur vidéo. Une instance appartient au thread qui l'a créée (objets
/// COM, sessions VideoToolbox).
pub trait VideoEncoder {
    /// Nom lisible, ex. « Media Foundation (NVIDIA H.264 Encoder MFT) ».
    fn name(&self) -> String;
    fn hardware(&self) -> bool;
    /// Encode une image aux dimensions de la configuration et rend les images
    /// encodées prêtes, dans l'ordre (souvent une seule ; aucune si
    /// l'encodeur la retient ou la saute).
    fn encode(&mut self, frame: &Frame, force_keyframe: bool) -> Result<Vec<EncodedFrame>>;
    /// Change le débit cible (débit adaptatif).
    fn set_bitrate(&mut self, bps: u32);
}

/// Préférence d'encodeur.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Preference {
    /// Matériel si possible, sinon logiciel.
    #[default]
    Auto,
    /// Logiciel uniquement (openh264).
    Software,
}

impl std::str::FromStr for Preference {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "auto" => Ok(Self::Auto),
            "software" | "logiciel" => Ok(Self::Software),
            _ => Err(format!("encodeur inconnu : {s} (auto, software)")),
        }
    }
}

type Factory = Box<dyn Fn(EncoderConfig) -> Result<Box<dyn VideoEncoder>>>;

fn candidates(pref: Preference) -> Vec<Factory> {
    let mut list: Vec<Factory> = Vec::new();
    if pref == Preference::Auto {
        #[cfg(windows)]
        for f in mf::factories() {
            list.push(f);
        }
        #[cfg(target_os = "macos")]
        list.push(Box::new(|c| {
            Ok(Box::new(vt::VideoToolboxEncoder::new(c)?) as Box<dyn VideoEncoder>)
        }));
    }
    list.push(Box::new(|c| {
        Ok(Box::new(OpenH264Encoder::new(c)?) as Box<dyn VideoEncoder>)
    }));
    list
}

/// Ouvre le meilleur encodeur H.264 disponible pour `config`.
pub fn open_h264(config: EncoderConfig, pref: Preference) -> Result<Chain> {
    let mut chain = Chain {
        config,
        factories: candidates(pref),
        next: 0,
        current: None,
        errors: Vec::new(),
    };
    chain.advance()?;
    Ok(chain)
}

/// Encodeur avec repli : si l'encodeur courant échoue, le suivant prend le
/// relais (image clé forcée).
pub struct Chain {
    config: EncoderConfig,
    factories: Vec<Factory>,
    next: usize,
    current: Option<Box<dyn VideoEncoder>>,
    errors: Vec<String>,
}

impl Chain {
    fn advance(&mut self) -> Result<()> {
        self.current = None;
        while self.next < self.factories.len() {
            let f = &self.factories[self.next];
            self.next += 1;
            match f(self.config) {
                Ok(e) => {
                    tracing::info!("encodeur H.264 : {}", e.name());
                    self.current = Some(e);
                    return Ok(());
                }
                Err(e) => {
                    tracing::debug!("encodeur indisponible : {e}");
                    self.errors.push(e.to_string());
                }
            }
        }
        Err(CodecError::NoEncoder(self.errors.join(" ; ")))
    }

    pub fn config(&self) -> &EncoderConfig {
        &self.config
    }
}

impl VideoEncoder for Chain {
    fn name(&self) -> String {
        self.current.as_ref().map(|e| e.name()).unwrap_or_default()
    }

    fn hardware(&self) -> bool {
        self.current.as_ref().is_some_and(|e| e.hardware())
    }

    fn encode(&mut self, frame: &Frame, force_keyframe: bool) -> Result<Vec<EncodedFrame>> {
        let mut force = force_keyframe;
        loop {
            let Some(e) = self.current.as_mut() else {
                return Err(CodecError::NoEncoder(self.errors.join(" ; ")));
            };
            match e.encode(frame, force) {
                Ok(out) => return Ok(out),
                Err(err) => {
                    tracing::warn!("{} a échoué ({err}), encodeur suivant", e.name());
                    self.errors.push(err.to_string());
                    self.advance()?;
                    force = true;
                }
            }
        }
    }

    fn set_bitrate(&mut self, bps: u32) {
        self.config.bitrate_bps = bps;
        if let Some(e) = &mut self.current {
            e.set_bitrate(bps);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gradient(w: u32, h: u32, shift: u32) -> Frame {
        let mut f = Frame::solid(w, h, [0, 0, 0, 255]);
        for y in 0..h as usize {
            for x in 0..w as usize {
                let i = y * f.stride + x * 4;
                f.data[i] = ((x as u32 + shift) % 256) as u8;
                f.data[i + 1] = (y % 256) as u8;
                f.data[i + 2] = 128;
            }
        }
        f
    }

    #[test]
    fn software_roundtrip() {
        let cfg = EncoderConfig::for_size(320, 240, 30);
        let mut enc = open_h264(cfg, Preference::Software).unwrap();
        assert!(!enc.hardware());
        let mut dec = H264Decoder::new().unwrap();
        let first = enc.encode(&gradient(320, 240, 0), false).unwrap().remove(0);
        assert!(first.keyframe && annexb::has_sps(&first.data));
        let img = dec.decode(&first.data).unwrap().unwrap();
        assert_eq!((img.width, img.height), (320, 240));
        // Pixel (100, 10) : B=100, G=10, R=128 à la compression près.
        let p = &img.rgba[(10 * 320 + 100) * 4..][..3];
        assert!(
            p[0].abs_diff(128) < 8 && p[1].abs_diff(10) < 8 && p[2].abs_diff(100) < 8,
            "{p:?}"
        );
        // Pixel (10, 10) : B=10, G=10, R=128 à la compression près.
        let p = &img.rgba[(10 * 320 + 10) * 4..][..3];
        assert!(p[0].abs_diff(128) < 12 && p[2].abs_diff(10) < 12, "{p:?}");

        let next = enc.encode(&gradient(320, 240, 4), false).unwrap().remove(0);
        assert!(!next.keyframe);
        dec.decode(&next.data).unwrap().unwrap();
        let forced = enc.encode(&gradient(320, 240, 8), true).unwrap().remove(0);
        assert!(forced.keyframe);
    }

    #[test]
    fn auto_always_finds_an_encoder() {
        let cfg = EncoderConfig::for_size(1280, 720, 30);
        assert!(cfg.bitrate_bps >= 1_000_000);
        let mut enc = open_h264(cfg, Preference::Auto).unwrap();
        let out = enc.encode(&gradient(1280, 720, 0), true).unwrap();
        // Un encodeur matériel peut différer la première image.
        if let Some(f) = out.first() {
            assert!(f.keyframe);
        }
    }

    #[test]
    fn bitrate_change_keeps_working() {
        let mut enc = open_h264(EncoderConfig::for_size(64, 64, 30), Preference::Software).unwrap();
        enc.encode(&gradient(64, 64, 0), false).unwrap();
        enc.set_bitrate(500_000);
        let f = enc.encode(&gradient(64, 64, 1), false).unwrap().remove(0);
        assert!(f.keyframe);
    }
}
