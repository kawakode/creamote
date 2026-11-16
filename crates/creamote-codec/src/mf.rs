//! Encodeurs H.264 Media Foundation (Windows 8+).
//!
//! Les MFT matériels des constructeurs (Intel Quick Sync, NVIDIA NVENC,
//! AMD AMF) sont asynchrones : ils signalent `METransformNeedInput` et
//! `METransformHaveOutput` par événements. L'encodeur logiciel de Microsoft
//! est synchrone. Les deux modes sont gérés ici, en entrée NV12 système.
#![allow(unsafe_code)]

use std::time::{Duration, Instant};

use creamote_capture::Frame;
use windows::Win32::Media::MediaFoundation::{
    CODECAPI_AVEncCommonMeanBitRate, CODECAPI_AVEncCommonRateControlMode,
    CODECAPI_AVEncMPVDefaultBPictureCount, CODECAPI_AVEncMPVGOPSize,
    CODECAPI_AVEncVideoForceKeyFrame, CODECAPI_AVLowLatencyMode, ICodecAPI, IMFActivate,
    IMFMediaEventGenerator, IMFMediaType, IMFSample, IMFTransform, METransformHaveOutput,
    METransformNeedInput, MF_E_NO_EVENTS_AVAILABLE, MF_E_TRANSFORM_NEED_MORE_INPUT,
    MF_E_TRANSFORM_STREAM_CHANGE, MF_EVENT_FLAG_NO_WAIT, MF_LOW_LATENCY, MF_MT_AVG_BITRATE,
    MF_MT_FRAME_RATE, MF_MT_FRAME_SIZE, MF_MT_INTERLACE_MODE, MF_MT_MAJOR_TYPE,
    MF_MT_MPEG_SEQUENCE_HEADER, MF_MT_SUBTYPE, MF_MT_VIDEO_NOMINAL_RANGE, MF_MT_YUV_MATRIX,
    MF_TRANSFORM_ASYNC, MF_TRANSFORM_ASYNC_UNLOCK, MF_VERSION, MFCreateMediaType,
    MFCreateMemoryBuffer, MFCreateSample, MFMediaType_Video, MFNominalRange_16_235, MFSTARTUP_FULL,
    MFSampleExtension_CleanPoint, MFStartup, MFT_CATEGORY_VIDEO_ENCODER, MFT_ENUM_FLAG,
    MFT_ENUM_FLAG_ASYNCMFT, MFT_ENUM_FLAG_HARDWARE, MFT_ENUM_FLAG_SORTANDFILTER,
    MFT_ENUM_FLAG_SYNCMFT, MFT_FRIENDLY_NAME_Attribute, MFT_MESSAGE_NOTIFY_BEGIN_STREAMING,
    MFT_MESSAGE_NOTIFY_START_OF_STREAM, MFT_OUTPUT_DATA_BUFFER,
    MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES, MFT_OUTPUT_STREAM_PROVIDES_SAMPLES,
    MFT_REGISTER_TYPE_INFO, MFTEnumEx, MFVideoFormat_H264, MFVideoFormat_NV12,
    MFVideoInterlace_Progressive, MFVideoTransferMatrix_BT709, eAVEncCommonRateControlMode_CBR,
};
use windows::Win32::System::Com::{COINIT_MULTITHREADED, CoInitializeEx, CoTaskMemFree};
use windows::Win32::System::Variant::VARIANT;
use windows::core::{Interface, PWSTR};

use crate::{CodecError, EncodedFrame, EncoderConfig, Factory, Result, VideoEncoder, annexb, yuv};

/// Attente maximale d'un événement d'un MFT asynchrone.
const EVENT_TIMEOUT: Duration = Duration::from_millis(500);

fn err(context: &str, e: windows::core::Error) -> CodecError {
    CodecError::Backend(format!("Media Foundation, {context} : {e}"))
}

fn startup() -> Result<()> {
    // SAFETY : initialisations idempotentes par thread / processus.
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        MFStartup(MF_VERSION, MFSTARTUP_FULL).map_err(|e| err("MFStartup", e))
    }
}

/// Une fabrique par MFT matériel trouvé, puis l'encodeur Microsoft.
pub(crate) fn factories() -> Vec<Factory> {
    let mut list: Vec<Factory> = Vec::new();
    for (hardware, flags) in [
        (true, MFT_ENUM_FLAG_HARDWARE | MFT_ENUM_FLAG_ASYNCMFT),
        (false, MFT_ENUM_FLAG_SYNCMFT),
    ] {
        let count = match enumerate(flags | MFT_ENUM_FLAG_SORTANDFILTER) {
            Ok(a) => a.len(),
            Err(e) => {
                tracing::debug!("{e}");
                0
            }
        };
        for index in 0..count {
            list.push(Box::new(move |c| {
                let mut all = enumerate(flags | MFT_ENUM_FLAG_SORTANDFILTER)?;
                if index >= all.len() {
                    return Err(CodecError::Backend("MFT disparu".into()));
                }
                let activate = all.swap_remove(index);
                Ok(Box::new(MfEncoder::new(activate, hardware, c)?) as Box<dyn VideoEncoder>)
            }));
        }
    }
    list
}

fn enumerate(flags: MFT_ENUM_FLAG) -> Result<Vec<IMFActivate>> {
    startup()?;
    let input = MFT_REGISTER_TYPE_INFO {
        guidMajorType: MFMediaType_Video,
        guidSubtype: MFVideoFormat_NV12,
    };
    let output = MFT_REGISTER_TYPE_INFO {
        guidMajorType: MFMediaType_Video,
        guidSubtype: MFVideoFormat_H264,
    };
    let mut ptr: *mut Option<IMFActivate> = std::ptr::null_mut();
    let mut count = 0u32;
    // SAFETY : le tableau retourné est alloué par COM ; chaque élément est
    // repris (move) puis le tableau libéré.
    unsafe {
        MFTEnumEx(
            MFT_CATEGORY_VIDEO_ENCODER,
            flags,
            Some(&input),
            Some(&output),
            &mut ptr,
            &mut count,
        )
        .map_err(|e| err("MFTEnumEx", e))?;
        let mut out = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            if let Some(a) = std::ptr::replace(ptr.add(i), None) {
                out.push(a);
            }
        }
        if !ptr.is_null() {
            CoTaskMemFree(Some(ptr as *const _));
        }
        Ok(out)
    }
}

fn friendly_name(a: &IMFActivate) -> String {
    let mut s = PWSTR::null();
    let mut len = 0u32;
    // SAFETY : chaîne allouée par COM, libérée après copie.
    unsafe {
        if a.GetAllocatedString(&MFT_FRIENDLY_NAME_Attribute, &mut s, &mut len)
            .is_err()
        {
            return "MFT H.264".into();
        }
        let name = s.to_string().unwrap_or_default();
        CoTaskMemFree(Some(s.0 as *const _));
        name
    }
}

pub(crate) struct MfEncoder {
    name: String,
    hardware: bool,
    config: EncoderConfig,
    activate: IMFActivate,
    transform: IMFTransform,
    events: Option<IMFMediaEventGenerator>,
    codec: Option<ICodecAPI>,
    /// Demandes d'entrée reçues et pas encore servies (mode asynchrone).
    need_input: u32,
    provides_samples: bool,
    output_size: u32,
    sequence_header: Vec<u8>,
    start: Instant,
    pending: Vec<(Instant, Instant)>,
}

fn media_type(subtype: &windows::core::GUID, c: &EncoderConfig) -> Result<IMFMediaType> {
    // SAFETY : objet COM créé localement.
    unsafe {
        let t = MFCreateMediaType().map_err(|e| err("MFCreateMediaType", e))?;
        let set = |r: windows::core::Result<()>| r.map_err(|e| err("type de média", e));
        set(t.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video))?;
        set(t.SetGUID(&MF_MT_SUBTYPE, subtype))?;
        set(t.SetUINT64(
            &MF_MT_FRAME_SIZE,
            (u64::from(c.width) << 32) | u64::from(c.height),
        ))?;
        set(t.SetUINT64(&MF_MT_FRAME_RATE, (u64::from(c.fps.max(1)) << 32) | 1))?;
        set(t.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32))?;
        set(t.SetUINT32(&MF_MT_YUV_MATRIX, MFVideoTransferMatrix_BT709.0 as u32))?;
        set(t.SetUINT32(&MF_MT_VIDEO_NOMINAL_RANGE, MFNominalRange_16_235.0 as u32))?;
        Ok(t)
    }
}

impl MfEncoder {
    fn new(activate: IMFActivate, hardware: bool, config: EncoderConfig) -> Result<Self> {
        let name = format!("Media Foundation ({})", friendly_name(&activate));
        // SAFETY : API COM ; toutes les interfaces sont comptées par référence.
        unsafe {
            let transform: IMFTransform = activate
                .ActivateObject()
                .map_err(|e| err("ActivateObject", e))?;
            let mut events = None;
            if let Ok(attrs) = transform.GetAttributes() {
                if attrs.GetUINT32(&MF_TRANSFORM_ASYNC).unwrap_or(0) == 1 {
                    attrs
                        .SetUINT32(&MF_TRANSFORM_ASYNC_UNLOCK, 1)
                        .map_err(|e| err("déverrouillage asynchrone", e))?;
                    events = Some(
                        transform
                            .cast::<IMFMediaEventGenerator>()
                            .map_err(|e| err("événements", e))?,
                    );
                }
                let _ = attrs.SetUINT32(&MF_LOW_LATENCY, 1);
            }
            let codec = transform.cast::<ICodecAPI>().ok();
            if let Some(api) = &codec {
                let set = |key, v: VARIANT| {
                    let _ = api.SetValue(key, &v);
                };
                set(&CODECAPI_AVLowLatencyMode, VARIANT::from(true));
                set(
                    &CODECAPI_AVEncCommonRateControlMode,
                    VARIANT::from(eAVEncCommonRateControlMode_CBR.0 as u32),
                );
                set(
                    &CODECAPI_AVEncCommonMeanBitRate,
                    VARIANT::from(config.bitrate_bps),
                );
                set(&CODECAPI_AVEncMPVDefaultBPictureCount, VARIANT::from(0u32));
                // GOP 0 : pas d'image clé périodique imposée.
                set(
                    &CODECAPI_AVEncMPVGOPSize,
                    VARIANT::from(config.keyframe_interval),
                );
            }

            // Les encodeurs exigent le type de sortie avant celui d'entrée.
            let out = media_type(&MFVideoFormat_H264, &config)?;
            out.SetUINT32(&MF_MT_AVG_BITRATE, config.bitrate_bps)
                .map_err(|e| err("débit", e))?;
            transform
                .SetOutputType(0, &out, 0)
                .map_err(|e| err("SetOutputType", e))?;
            let input = media_type(&MFVideoFormat_NV12, &config)?;
            transform
                .SetInputType(0, &input, 0)
                .map_err(|e| err("SetInputType NV12", e))?;

            let info = transform
                .GetOutputStreamInfo(0)
                .map_err(|e| err("GetOutputStreamInfo", e))?;
            let provides = info.dwFlags
                & (MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 | MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES.0)
                    as u32
                != 0;
            let sequence_header = sequence_header(&transform);

            transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)
                .map_err(|e| err("BEGIN_STREAMING", e))?;
            transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)
                .map_err(|e| err("START_OF_STREAM", e))?;

            Ok(Self {
                name,
                hardware,
                config,
                activate,
                transform,
                events,
                codec,
                need_input: 0,
                provides_samples: provides,
                output_size: info.cbSize.max(config.width * config.height),
                sequence_header,
                start: Instant::now(),
                pending: Vec::new(),
            })
        }
    }

    fn input_sample(&self, frame: &Frame) -> Result<IMFSample> {
        let nv12 = yuv::to_nv12(frame);
        // SAFETY : tampon verrouillé pendant la copie de `nv12.len()` octets,
        // taille allouée identique.
        unsafe {
            let buffer = MFCreateMemoryBuffer(nv12.len() as u32)
                .map_err(|e| err("MFCreateMemoryBuffer", e))?;
            let mut ptr = std::ptr::null_mut();
            buffer
                .Lock(&mut ptr, None, None)
                .map_err(|e| err("Lock", e))?;
            std::ptr::copy_nonoverlapping(nv12.as_ptr(), ptr, nv12.len());
            buffer.Unlock().map_err(|e| err("Unlock", e))?;
            buffer
                .SetCurrentLength(nv12.len() as u32)
                .map_err(|e| err("SetCurrentLength", e))?;
            let sample = MFCreateSample().map_err(|e| err("MFCreateSample", e))?;
            sample.AddBuffer(&buffer).map_err(|e| err("AddBuffer", e))?;
            let t = frame.captured_at.saturating_duration_since(self.start);
            sample
                .SetSampleTime((t.as_nanos() / 100) as i64)
                .map_err(|e| err("SetSampleTime", e))?;
            sample
                .SetSampleDuration(10_000_000 / i64::from(self.config.fps.max(1)))
                .map_err(|e| err("SetSampleDuration", e))?;
            Ok(sample)
        }
    }

    /// Récupère une image encodée ; `Ok(None)` si l'encodeur en veut plus.
    fn pull(&mut self) -> Result<Option<EncodedFrame>> {
        // SAFETY : ProcessOutput remplit la structure ; l'échantillon et la
        // collection d'événements sont repris pour être libérés.
        unsafe {
            let own = if self.provides_samples {
                None
            } else {
                let s = MFCreateSample().map_err(|e| err("MFCreateSample", e))?;
                let b = MFCreateMemoryBuffer(self.output_size)
                    .map_err(|e| err("MFCreateMemoryBuffer", e))?;
                s.AddBuffer(&b).map_err(|e| err("AddBuffer", e))?;
                Some(s)
            };
            let mut out = [MFT_OUTPUT_DATA_BUFFER {
                dwStreamID: 0,
                pSample: std::mem::ManuallyDrop::new(own),
                dwStatus: 0,
                pEvents: std::mem::ManuallyDrop::new(None),
            }];
            let mut status = 0u32;
            let r = self.transform.ProcessOutput(0, &mut out, &mut status);
            let sample = std::mem::ManuallyDrop::take(&mut out[0].pSample);
            drop(std::mem::ManuallyDrop::take(&mut out[0].pEvents));
            match r {
                Ok(()) => {}
                Err(e) if e.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => return Ok(None),
                Err(e) if e.code() == MF_E_TRANSFORM_STREAM_CHANGE => {
                    let t = self
                        .transform
                        .GetOutputAvailableType(0, 0)
                        .map_err(|e| err("GetOutputAvailableType", e))?;
                    self.transform
                        .SetOutputType(0, &t, 0)
                        .map_err(|e| err("SetOutputType", e))?;
                    self.sequence_header = sequence_header(&self.transform);
                    return Ok(None);
                }
                Err(e) => return Err(err("ProcessOutput", e)),
            }
            let Some(sample) = sample else {
                return Ok(None);
            };
            let buffer = sample
                .ConvertToContiguousBuffer()
                .map_err(|e| err("ConvertToContiguousBuffer", e))?;
            let mut ptr = std::ptr::null_mut();
            let mut len = 0u32;
            buffer
                .Lock(&mut ptr, None, Some(&mut len))
                .map_err(|e| err("Lock", e))?;
            let bytes = std::slice::from_raw_parts(ptr, len as usize).to_vec();
            let _ = buffer.Unlock();
            let keyframe = sample.GetUINT32(&MFSampleExtension_CleanPoint).unwrap_or(0) == 1
                || annexb::is_keyframe(&bytes);
            let mut data = Vec::with_capacity(bytes.len() + self.sequence_header.len());
            if keyframe && !annexb::has_sps(&bytes) {
                data.extend_from_slice(&self.sequence_header);
            }
            data.extend_from_slice(&bytes);
            let captured_at = if self.pending.is_empty() {
                Instant::now()
            } else {
                self.pending.remove(0).0
            };
            Ok(Some(EncodedFrame {
                data,
                keyframe,
                captured_at,
            }))
        }
    }

    /// Mode asynchrone : traite les événements et ajoute les sorties à `out`,
    /// jusqu'à une demande d'entrée (`want_input`) ou une première sortie.
    fn pump(&mut self, want_input: bool, out: &mut Vec<EncodedFrame>) -> Result<()> {
        let Some(events) = self.events.clone() else {
            return Ok(());
        };
        let deadline = Instant::now() + EVENT_TIMEOUT;
        loop {
            if want_input && self.need_input > 0 {
                return Ok(());
            }
            // SAFETY : API COM.
            match unsafe { events.GetEvent(MF_EVENT_FLAG_NO_WAIT) } {
                Ok(ev) => {
                    let kind = unsafe { ev.GetType() }.map_err(|e| err("GetType", e))?;
                    if kind == METransformNeedInput.0 as u32 {
                        self.need_input += 1;
                    } else if kind == METransformHaveOutput.0 as u32
                        && let Some(f) = self.pull()?
                    {
                        out.push(f);
                        if !want_input {
                            return Ok(());
                        }
                    }
                }
                Err(e) if e.code() == MF_E_NO_EVENTS_AVAILABLE => {
                    if Instant::now() >= deadline {
                        if want_input {
                            return Err(CodecError::Backend(format!(
                                "{} ne demande pas d'image",
                                self.name
                            )));
                        }
                        return Ok(());
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) => return Err(err("GetEvent", e)),
            }
        }
    }
}

fn sequence_header(t: &IMFTransform) -> Vec<u8> {
    // SAFETY : lecture d'un blob d'attribut dans un tampon de taille exacte.
    unsafe {
        let Ok(ty) = t.GetOutputCurrentType(0) else {
            return Vec::new();
        };
        let Ok(size) = ty.GetBlobSize(&MF_MT_MPEG_SEQUENCE_HEADER) else {
            return Vec::new();
        };
        let mut buf = vec![0u8; size as usize];
        if ty
            .GetBlob(&MF_MT_MPEG_SEQUENCE_HEADER, &mut buf, None)
            .is_err()
        {
            return Vec::new();
        }
        buf
    }
}

impl VideoEncoder for MfEncoder {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn hardware(&self) -> bool {
        self.hardware
    }

    fn encode(&mut self, frame: &Frame, force_keyframe: bool) -> Result<Vec<EncodedFrame>> {
        let (w, h) = yuv::even_dims(frame.width, frame.height);
        if (w, h) != (self.config.width, self.config.height) {
            return Err(CodecError::Backend(format!(
                "taille {w}×{h} différente de la configuration"
            )));
        }
        if force_keyframe && let Some(api) = &self.codec {
            // SAFETY : API COM.
            let _ =
                unsafe { api.SetValue(&CODECAPI_AVEncVideoForceKeyFrame, &VARIANT::from(1u32)) };
        }
        let sample = self.input_sample(frame)?;
        let mut out = Vec::new();
        if self.events.is_some() {
            self.pump(true, &mut out)?;
            self.need_input -= 1;
        }
        // SAFETY : API COM.
        unsafe { self.transform.ProcessInput(0, &sample, 0) }
            .map_err(|e| err("ProcessInput", e))?;
        self.pending.push((frame.captured_at, Instant::now()));
        if self.events.is_some() {
            // Attend la sortie de cette image (latence minimale).
            if out.is_empty() {
                self.pump(false, &mut out)?;
            }
        } else {
            while let Some(f) = self.pull()? {
                out.push(f);
            }
        }
        Ok(out)
    }

    fn set_bitrate(&mut self, bps: u32) {
        self.config.bitrate_bps = bps;
        if let Some(api) = &self.codec {
            // SAFETY : API COM.
            let _ = unsafe { api.SetValue(&CODECAPI_AVEncCommonMeanBitRate, &VARIANT::from(bps)) };
        }
    }
}

impl Drop for MfEncoder {
    fn drop(&mut self) {
        // SAFETY : libère l'instance MFT créée par ActivateObject.
        let _ = unsafe { self.activate.ShutdownObject() };
    }
}
