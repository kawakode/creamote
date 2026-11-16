//! Encodeur H.264 VideoToolbox (macOS) : encodeur matériel Apple (Apple
//! Silicon, Intel Quick Sync sur les Mac Intel), conversion BGRA → YUV
//! comprise. Repli logiciel d'Apple si le matériel est occupé.
#![allow(unsafe_code)]

use std::ptr::NonNull;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use block2::RcBlock;
use creamote_capture::Frame;
use objc2_core_foundation::{CFBoolean, CFDictionary, CFNumber, CFRetained, CFString, CFType};
use objc2_core_media::{
    CMSampleBuffer, CMTime, CMVideoFormatDescriptionGetH264ParameterSetAtIndex, kCMTimeInvalid,
    kCMVideoCodecType_H264,
};
use objc2_core_video::{
    CVPixelBuffer, CVPixelBufferCreate, CVPixelBufferGetBaseAddress, CVPixelBufferGetBytesPerRow,
    CVPixelBufferLockBaseAddress, CVPixelBufferLockFlags, CVPixelBufferUnlockBaseAddress,
    kCVImageBufferColorPrimaries_ITU_R_709_2, kCVImageBufferTransferFunction_ITU_R_709_2,
    kCVImageBufferYCbCrMatrix_ITU_R_709_2, kCVPixelFormatType_32BGRA, kCVReturnSuccess,
};
use objc2_video_toolbox::{
    VTCompressionSession, VTEncodeInfoFlags, VTSessionCopyProperty, VTSessionSetProperty,
    kVTCompressionPropertyKey_AllowFrameReordering, kVTCompressionPropertyKey_AverageBitRate,
    kVTCompressionPropertyKey_ColorPrimaries, kVTCompressionPropertyKey_ExpectedFrameRate,
    kVTCompressionPropertyKey_MaxKeyFrameInterval, kVTCompressionPropertyKey_ProfileLevel,
    kVTCompressionPropertyKey_RealTime, kVTCompressionPropertyKey_TransferFunction,
    kVTCompressionPropertyKey_UsingHardwareAcceleratedVideoEncoder,
    kVTCompressionPropertyKey_YCbCrMatrix, kVTEncodeFrameOptionKey_ForceKeyFrame,
    kVTProfileLevel_H264_Main_AutoLevel,
    kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder,
};

use crate::{CodecError, EncodedFrame, EncoderConfig, Result, VideoEncoder, annexb, yuv};

fn status(context: &str, s: i32) -> Result<()> {
    if s == 0 {
        Ok(())
    } else {
        Err(CodecError::Backend(format!(
            "VideoToolbox, {context} : OSStatus {s}"
        )))
    }
}

type Output = Arc<Mutex<Vec<Result<(Vec<u8>, bool)>>>>;

pub(crate) struct VideoToolboxEncoder {
    session: CFRetained<VTCompressionSession>,
    config: EncoderConfig,
    hardware: bool,
    start: Instant,
    output: Output,
}

fn set(session: &VTCompressionSession, key: &CFString, value: &CFType) {
    // SAFETY : clé et valeur du type documenté pour la propriété.
    let s = unsafe { VTSessionSetProperty(session, key, Some(value)) };
    if s != 0 {
        tracing::debug!("VideoToolbox : propriété {key} refusée ({s})");
    }
}

impl VideoToolboxEncoder {
    pub(crate) fn new(config: EncoderConfig) -> Result<Self> {
        // SAFETY : appels VideoToolbox avec des objets CF valides ; la session
        // créée est reprise par CFRetained.
        unsafe {
            let spec = CFDictionary::<CFString, CFType>::from_slices(
                &[kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder],
                &[CFBoolean::new(true)],
            );
            let mut raw: *mut VTCompressionSession = std::ptr::null_mut();
            status(
                "VTCompressionSessionCreate",
                VTCompressionSession::create(
                    None,
                    config.width as i32,
                    config.height as i32,
                    kCMVideoCodecType_H264,
                    Some(spec.as_opaque()),
                    None,
                    None,
                    None,
                    std::ptr::null_mut(),
                    NonNull::from(&mut raw),
                ),
            )?;
            let session = CFRetained::from_raw(
                NonNull::new(raw).ok_or_else(|| CodecError::Backend("session nulle".into()))?,
            );
            let s: &VTCompressionSession = &session;
            set(s, kVTCompressionPropertyKey_RealTime, CFBoolean::new(true));
            set(
                s,
                kVTCompressionPropertyKey_AllowFrameReordering,
                CFBoolean::new(false),
            );
            set(
                s,
                kVTCompressionPropertyKey_ProfileLevel,
                kVTProfileLevel_H264_Main_AutoLevel,
            );
            set(
                s,
                kVTCompressionPropertyKey_AverageBitRate,
                &CFNumber::new_i64(i64::from(config.bitrate_bps)),
            );
            set(
                s,
                kVTCompressionPropertyKey_ExpectedFrameRate,
                &CFNumber::new_i32(config.fps as i32),
            );
            // 0 : pas de limite (images clés à la demande).
            set(
                s,
                kVTCompressionPropertyKey_MaxKeyFrameInterval,
                &CFNumber::new_i32(config.keyframe_interval as i32),
            );
            set(
                s,
                kVTCompressionPropertyKey_ColorPrimaries,
                kCVImageBufferColorPrimaries_ITU_R_709_2,
            );
            set(
                s,
                kVTCompressionPropertyKey_TransferFunction,
                kCVImageBufferTransferFunction_ITU_R_709_2,
            );
            set(
                s,
                kVTCompressionPropertyKey_YCbCrMatrix,
                kCVImageBufferYCbCrMatrix_ITU_R_709_2,
            );

            let mut hw: *const CFType = std::ptr::null();
            let hardware = VTSessionCopyProperty(
                s,
                kVTCompressionPropertyKey_UsingHardwareAcceleratedVideoEncoder,
                None,
                &mut hw as *mut *const CFType as *mut _,
            ) == 0
                && !hw.is_null()
                && {
                    let v = CFRetained::from_raw(NonNull::new_unchecked(hw as *mut CFType));
                    v.downcast_ref::<CFBoolean>().is_some_and(|b| b.as_bool())
                };
            Ok(Self {
                session,
                config,
                hardware,
                start: Instant::now(),
                output: Arc::default(),
            })
        }
    }

    fn pixel_buffer(&self, frame: &Frame) -> Result<CFRetained<CVPixelBuffer>> {
        let (w, h) = (self.config.width, self.config.height);
        // SAFETY : tampon créé à la taille de la configuration, verrouillé
        // pendant la copie ligne par ligne (pas de destination respecté).
        unsafe {
            let mut raw: *mut CVPixelBuffer = std::ptr::null_mut();
            let r = CVPixelBufferCreate(
                None,
                w as usize,
                h as usize,
                kCVPixelFormatType_32BGRA,
                None,
                NonNull::from(&mut raw),
            );
            if r != kCVReturnSuccess {
                return Err(CodecError::Backend(format!("CVPixelBufferCreate : {r}")));
            }
            let pb = CFRetained::from_raw(
                NonNull::new(raw).ok_or_else(|| CodecError::Backend("tampon nul".into()))?,
            );
            CVPixelBufferLockBaseAddress(&pb, CVPixelBufferLockFlags(0));
            let dst = CVPixelBufferGetBaseAddress(&pb) as *mut u8;
            let pitch = CVPixelBufferGetBytesPerRow(&pb);
            for y in 0..h as usize {
                let row = &frame.row(y)[..w as usize * 4];
                std::ptr::copy_nonoverlapping(row.as_ptr(), dst.add(y * pitch), row.len());
            }
            CVPixelBufferUnlockBaseAddress(&pb, CVPixelBufferLockFlags(0));
            Ok(pb)
        }
    }
}

/// Convertit un échantillon AVCC de VideoToolbox en Annex B, avec SPS/PPS
/// en tête des images clés.
fn sample_to_annexb(sample: &CMSampleBuffer) -> Result<(Vec<u8>, bool)> {
    // SAFETY : lecture d'objets CoreMedia valides pendant le rappel.
    unsafe {
        let block = sample
            .data_buffer()
            .ok_or_else(|| CodecError::Backend("échantillon sans données".into()))?;
        let len = block.data_length();
        let mut avcc = vec![0u8; len];
        status(
            "CMBlockBufferCopyDataBytes",
            block.copy_data_bytes(0, len, NonNull::new_unchecked(avcc.as_mut_ptr().cast())),
        )?;
        // Longueur des préfixes NAL et paramètres de séquence.
        let mut out = Vec::with_capacity(len + 64);
        let mut header_len: i32 = 4;
        let desc = sample.format_description();
        let mut params = Vec::new();
        if let Some(desc) = &desc {
            let mut count = 0usize;
            let mut ptr: *const u8 = std::ptr::null();
            let mut size = 0usize;
            if CMVideoFormatDescriptionGetH264ParameterSetAtIndex(
                desc,
                0,
                &mut ptr,
                &mut size,
                &mut count,
                &mut header_len,
            ) == 0
            {
                for i in 0..count {
                    if CMVideoFormatDescriptionGetH264ParameterSetAtIndex(
                        desc,
                        i,
                        &mut ptr,
                        &mut size,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    ) == 0
                    {
                        params.extend_from_slice(&[0, 0, 0, 1]);
                        params.extend_from_slice(std::slice::from_raw_parts(ptr, size));
                    }
                }
            }
        }
        let mut body = Vec::with_capacity(len + 16);
        if !annexb::avcc_to_annexb(&avcc, header_len.clamp(1, 4) as usize, &mut body) {
            return Err(CodecError::Backend("échantillon AVCC invalide".into()));
        }
        let keyframe = annexb::is_keyframe(&body);
        if keyframe {
            out.extend_from_slice(&params);
        }
        out.extend_from_slice(&body);
        Ok((out, keyframe))
    }
}

impl VideoEncoder for VideoToolboxEncoder {
    fn name(&self) -> String {
        if self.hardware {
            "VideoToolbox (matériel)".into()
        } else {
            "VideoToolbox (logiciel Apple)".into()
        }
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
        let pb = self.pixel_buffer(frame)?;
        let output = self.output.clone();
        let handler = RcBlock::new(
            move |s: i32, _flags: VTEncodeInfoFlags, sample: *mut CMSampleBuffer| {
                let r = if s != 0 {
                    Err(CodecError::Backend(format!("encodage : OSStatus {s}")))
                } else {
                    // SAFETY : échantillon valide pendant le rappel (ou nul
                    // si l'image a été sautée).
                    match unsafe { sample.as_ref() } {
                        Some(sample) => sample_to_annexb(sample),
                        None => return,
                    }
                };
                output.lock().unwrap_or_else(|e| e.into_inner()).push(r);
            },
        );
        let t = frame.captured_at.saturating_duration_since(self.start);
        // SAFETY : session, tampon et bloc valides pendant l'appel ; la
        // session les retient au besoin.
        unsafe {
            let props = force_keyframe.then(|| {
                CFDictionary::<CFString, CFType>::from_slices(
                    &[kVTEncodeFrameOptionKey_ForceKeyFrame],
                    &[CFBoolean::new(true)],
                )
            });
            status(
                "VTCompressionSessionEncodeFrame",
                self.session.encode_frame_with_output_handler(
                    &pb,
                    CMTime::new(t.as_micros() as i64, 1_000_000),
                    kCMTimeInvalid,
                    props.as_deref().map(|d| d.as_opaque()),
                    std::ptr::null_mut(),
                    RcBlock::as_ptr(&handler),
                ),
            )?;
            // Pas d'images B : on vide l'encodeur à chaque image (latence
            // minimale, la sortie arrive dans le rappel ci-dessus).
            status(
                "VTCompressionSessionCompleteFrames",
                self.session.complete_frames(kCMTimeInvalid),
            )?;
        }
        let results = std::mem::take(&mut *self.output.lock().unwrap_or_else(|e| e.into_inner()));
        results
            .into_iter()
            .map(|r| {
                r.map(|(data, keyframe)| EncodedFrame {
                    data,
                    keyframe,
                    captured_at: frame.captured_at,
                })
            })
            .collect()
    }

    fn set_bitrate(&mut self, bps: u32) {
        self.config.bitrate_bps = bps;
        set(
            &self.session,
            // SAFETY : clé statique fournie par VideoToolbox.
            unsafe { kVTCompressionPropertyKey_AverageBitRate },
            &CFNumber::new_i64(i64::from(bps)),
        );
    }
}

impl Drop for VideoToolboxEncoder {
    fn drop(&mut self) {
        // SAFETY : invalide la session avant sa libération.
        unsafe { self.session.invalidate() };
    }
}
