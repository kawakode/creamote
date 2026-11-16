//! Encodeur et décodeur logiciels openh264 (Cisco, BSD), compilés depuis les
//! sources. Repli quand aucun encodeur matériel n'est disponible (machine
//! virtuelle, Linux en attendant VA-API) et décodeur du viewer sans WebCodecs.

use openh264::OpenH264API;
use openh264::decoder::Decoder;
use openh264::encoder::{
    BitRate, Complexity, Encoder, EncoderConfig as OhConfig, FrameRate, FrameType,
    IntraFramePeriod, RateControlMode, UsageType, VuiConfig,
};
use openh264::formats::{YUVSlices, YUVSource};

use crate::{CodecError, EncodedFrame, EncoderConfig, Result, VideoEncoder, yuv};
use creamote_capture::Frame;

fn err(e: openh264::Error) -> CodecError {
    CodecError::Backend(format!("openh264 : {e}"))
}

pub struct OpenH264Encoder {
    config: EncoderConfig,
    encoder: Option<Encoder>,
}

impl OpenH264Encoder {
    pub fn new(config: EncoderConfig) -> Result<Self> {
        let mut e = Self {
            config,
            encoder: None,
        };
        e.encoder = Some(e.create()?);
        Ok(e)
    }

    fn create(&self) -> Result<Encoder> {
        let c = &self.config;
        let cfg = OhConfig::new()
            .usage_type(UsageType::ScreenContentRealTime)
            .rate_control_mode(RateControlMode::Bitrate)
            .bitrate(BitRate::from_bps(c.bitrate_bps))
            .max_frame_rate(FrameRate::from_hz(c.fps as f32))
            // Sans saut d'images, openh264 ne tient pas le débit cible.
            .skip_frames(true)
            .adaptive_quantization(false)
            .background_detection(false)
            .complexity(Complexity::Low)
            .intra_frame_period(IntraFramePeriod::from_num_frames(c.keyframe_interval))
            .num_threads(4)
            .vui(VuiConfig::bt709());
        Encoder::with_api_config(OpenH264API::from_source(), cfg).map_err(err)
    }
}

impl VideoEncoder for OpenH264Encoder {
    fn name(&self) -> String {
        "openh264 (logiciel)".into()
    }

    fn hardware(&self) -> bool {
        false
    }

    fn encode(&mut self, frame: &Frame, force_keyframe: bool) -> Result<Vec<EncodedFrame>> {
        let encoder = match &mut self.encoder {
            Some(e) => e,
            None => self.encoder.insert(self.create()?),
        };
        let i = yuv::to_i420(frame);
        if i.width == 0 || i.height == 0 {
            return Ok(Vec::new());
        }
        let src = YUVSlices::new(
            (&i.y, &i.u, &i.v),
            (i.width, i.height),
            (i.width, i.width / 2, i.width / 2),
        );
        if force_keyframe {
            encoder.force_intra_frame();
        }
        let bs = encoder.encode(&src).map_err(err)?;
        if matches!(bs.frame_type(), FrameType::Skip | FrameType::Invalid) {
            return Ok(Vec::new());
        }
        let data = bs.to_vec();
        if data.is_empty() {
            return Ok(Vec::new());
        }
        Ok(vec![EncodedFrame {
            keyframe: matches!(bs.frame_type(), FrameType::IDR | FrameType::I),
            data,
            captured_at: frame.captured_at,
        }])
    }

    fn set_bitrate(&mut self, bps: u32) {
        if bps != self.config.bitrate_bps {
            self.config.bitrate_bps = bps;
            // openh264 ne change pas le débit sans réinitialisation : le
            // prochain encodage recrée l'encodeur (et émet une image clé).
            self.encoder = None;
        }
    }
}

/// Image décodée en RGBA 8 bits compact.
pub struct DecodedFrame {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

/// Décodeur H.264 logiciel (Annex B).
pub struct H264Decoder {
    decoder: Decoder,
}

impl H264Decoder {
    pub fn new() -> Result<Self> {
        Ok(Self {
            decoder: Decoder::new().map_err(err)?,
        })
    }

    /// Décode une image complète ; `None` si le décodeur attend la suite.
    pub fn decode(&mut self, annexb: &[u8]) -> Result<Option<DecodedFrame>> {
        let Some(yuv) = self.decoder.decode(annexb).map_err(err)? else {
            return Ok(None);
        };
        let (w, h) = yuv.dimensions();
        let (ys, us, _) = yuv.strides();
        let mut rgba = vec![0; w * h * 4];
        // Conversion BT.709 (celle que signalent nos encodeurs), pas BT.601.
        yuv::i420_to_rgba(w, h, yuv.y(), yuv.u(), yuv.v(), ys, us, &mut rgba);
        Ok(Some(DecodedFrame {
            width: w as u32,
            height: h as u32,
            rgba,
        }))
    }
}
