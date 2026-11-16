//! Capture macOS par ScreenCaptureKit (macOS 12.3+). Le système livre les
//! images dans un `CVPixelBuffer` BGRA sur une file GCD, uniquement quand
//! l'écran change ; le curseur est incrusté par le système.
//!
//! Nécessite l'autorisation « Enregistrement de l'écran » (Réglages Système >
//! Confidentialité et sécurité), demandée au premier lancement.
#![allow(unsafe_code)]

use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::time::{Duration, Instant};

use block2::RcBlock;
use dispatch2::DispatchQueue;
use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2::{AllocAnyThread, DefinedClass, define_class, msg_send};
use objc2_core_graphics::{
    CGDisplayCopyDisplayMode, CGDisplayMode, CGMainDisplayID, CGPreflightScreenCaptureAccess,
    CGRequestScreenCaptureAccess,
};
use objc2_core_media::{CMSampleBuffer, CMTime};
use objc2_core_video::{
    CVPixelBufferGetBaseAddress, CVPixelBufferGetBytesPerRow, CVPixelBufferGetHeight,
    CVPixelBufferGetWidth, CVPixelBufferLockBaseAddress, CVPixelBufferLockFlags,
    CVPixelBufferUnlockBaseAddress, kCVPixelFormatType_32BGRA, kCVReturnSuccess,
};
use objc2_foundation::{NSArray, NSError, NSObject, NSObjectProtocol};
use objc2_screen_capture_kit::{
    SCContentFilter, SCDisplay, SCShareableContent, SCStream, SCStreamConfiguration,
    SCStreamOutput, SCStreamOutputType,
};

use crate::{CaptureError, Capturer, DisplayInfo, Frame, Result, copy_rows};

const PERMISSION_HINT: &str = " : autorisez ce programme dans Réglages Système > Confidentialité et \
     sécurité > Enregistrement de l'écran, puis relancez-le";

/// Délai des appels asynchrones de ScreenCaptureKit.
const CALL_TIMEOUT: Duration = Duration::from_secs(10);

pub fn init() {}

/// Les objets Objective-C transitent du thread GCD vers le thread appelant ;
/// ils ne sont utilisés que par ce dernier ensuite.
struct SendBox<T>(T);
unsafe impl<T> Send for SendBox<T> {}

fn ns_error(context: &str, e: *mut NSError) -> CaptureError {
    // SAFETY : pointeur d'erreur fourni par le système, nul ou valide.
    let msg = unsafe { e.as_ref() }
        .map(|e| e.localizedDescription().to_string())
        .unwrap_or_else(|| "erreur inconnue".into());
    CaptureError::Backend(format!("{context} : {msg}"))
}

fn check_permission() -> Result<()> {
    if CGPreflightScreenCaptureAccess() {
        return Ok(());
    }
    // Affiche la demande système (une seule fois par application).
    CGRequestScreenCaptureAccess();
    Err(CaptureError::PermissionDenied(PERMISSION_HINT))
}

fn shareable_content() -> Result<Retained<SCShareableContent>> {
    check_permission()?;
    let (tx, rx) = sync_channel(1);
    let block = RcBlock::new(
        move |content: *mut SCShareableContent, error: *mut NSError| {
            // SAFETY : objet fourni par le système, retenu avant de quitter le bloc.
            let r = match unsafe { Retained::retain(content) } {
                Some(c) => Ok(SendBox(c)),
                None => Err(ns_error("SCShareableContent", error)),
            };
            let _ = tx.try_send(r);
        },
    );
    // SAFETY : le bloc est retenu par le système pendant l'appel.
    unsafe { SCShareableContent::getShareableContentWithCompletionHandler(&block) };
    match rx.recv_timeout(CALL_TIMEOUT) {
        Ok(r) => r.map(|b| b.0),
        Err(_) => Err(CaptureError::Backend(
            "ScreenCaptureKit ne répond pas".into(),
        )),
    }
}

fn info(d: &SCDisplay) -> DisplayInfo {
    // SAFETY : accesseurs en lecture seule.
    let (id, frame, w_points) = unsafe { (d.displayID(), d.frame(), d.width()) };
    let mode = CGDisplayCopyDisplayMode(id);
    let pw = CGDisplayMode::pixel_width(mode.as_deref());
    let ph = CGDisplayMode::pixel_height(mode.as_deref());
    let (width, height) = if pw > 0 && ph > 0 {
        (pw as u32, ph as u32)
    } else {
        (frame.size.width as u32, frame.size.height as u32)
    };
    DisplayInfo {
        id,
        name: format!("Écran {id}"),
        x: frame.origin.x as i32,
        y: frame.origin.y as i32,
        width,
        height,
        scale: if w_points > 0 {
            width as f32 / w_points as f32
        } else {
            1.0
        },
        primary: id == CGMainDisplayID(),
    }
}

pub fn displays() -> Result<Vec<DisplayInfo>> {
    let content = shareable_content()?;
    // SAFETY : accesseur en lecture seule.
    let displays = unsafe { content.displays() };
    Ok(displays.iter().map(|d| info(&d)).collect())
}

struct OutputIvars {
    tx: SyncSender<Frame>,
}

define_class!(
    // SAFETY : NSObject n'impose rien aux sous-classes ; pas de Drop.
    #[unsafe(super(NSObject))]
    #[ivars = OutputIvars]
    struct StreamOutput;

    unsafe impl NSObjectProtocol for StreamOutput {}

    unsafe impl SCStreamOutput for StreamOutput {
        #[unsafe(method(stream:didOutputSampleBuffer:ofType:))]
        fn did_output(
            &self,
            _stream: &SCStream,
            sample: &CMSampleBuffer,
            kind: SCStreamOutputType,
        ) {
            if kind != SCStreamOutputType::Screen {
                return;
            }
            if let Some(frame) = copy_sample(sample) {
                // File pleine : le consommateur est en retard, on jette
                // l'image (la suivante arrivera au prochain changement).
                if let Err(TrySendError::Disconnected(_)) = self.ivars().tx.try_send(frame) {}
            }
        }
    }
);

impl StreamOutput {
    fn new(tx: SyncSender<Frame>) -> Retained<Self> {
        let this = Self::alloc().set_ivars(OutputIvars { tx });
        // SAFETY : init de NSObject.
        unsafe { msg_send![super(this), init] }
    }
}

/// Copie l'image d'un échantillon ; `None` pour les échantillons sans image
/// (écran inchangé, image partielle).
fn copy_sample(sample: &CMSampleBuffer) -> Option<Frame> {
    let captured_at = Instant::now();
    // SAFETY : échantillon valide pendant l'appel ; le tampon est verrouillé
    // en lecture pendant la copie.
    unsafe {
        let pb = sample.image_buffer()?;
        if CVPixelBufferLockBaseAddress(&pb, CVPixelBufferLockFlags::ReadOnly) != kCVReturnSuccess {
            return None;
        }
        let width = CVPixelBufferGetWidth(&pb) as u32;
        let height = CVPixelBufferGetHeight(&pb) as u32;
        let stride = CVPixelBufferGetBytesPerRow(&pb);
        let base = CVPixelBufferGetBaseAddress(&pb) as *const u8;
        let frame = (!base.is_null()).then(|| {
            let src = std::slice::from_raw_parts(base, stride * height as usize);
            Frame {
                width,
                height,
                stride: width as usize * 4,
                data: copy_rows(src, stride, width, height),
                captured_at,
            }
        });
        CVPixelBufferUnlockBaseAddress(&pb, CVPixelBufferLockFlags::ReadOnly);
        frame
    }
}

pub fn open(display: DisplayInfo) -> Result<Box<dyn Capturer>> {
    let content = shareable_content()?;
    // SAFETY : accesseurs en lecture seule.
    let sc_display = unsafe { content.displays() }
        .iter()
        .find(|d| unsafe { d.displayID() } == display.id)
        .ok_or(CaptureError::UnknownDisplay(display.id))?;

    let (tx, frames) = sync_channel(2);
    let output = StreamOutput::new(tx);
    let queue = DispatchQueue::new("org.creamote.capture", None);
    // SAFETY : objets valides ; le flux, la sortie et la file sont conservés
    // par le capteur jusqu'à l'arrêt.
    let stream = unsafe {
        let filter = SCContentFilter::initWithDisplay_excludingWindows(
            SCContentFilter::alloc(),
            &sc_display,
            &NSArray::new(),
        );
        let config = SCStreamConfiguration::new();
        config.setWidth(display.width as usize);
        config.setHeight(display.height as usize);
        config.setPixelFormat(kCVPixelFormatType_32BGRA);
        config.setMinimumFrameInterval(CMTime::new(1, 60));
        config.setShowsCursor(true);
        config.setQueueDepth(5);
        config.setCapturesAudio(false);
        let stream = SCStream::initWithFilter_configuration_delegate(
            SCStream::alloc(),
            &filter,
            &config,
            None,
        );
        stream
            .addStreamOutput_type_sampleHandlerQueue_error(
                ProtocolObject::from_ref(&*output),
                SCStreamOutputType::Screen,
                Some(&queue),
            )
            .map_err(|e| ns_error("addStreamOutput", Retained::as_ptr(&e) as *mut _))?;
        stream
    };
    let (tx, rx) = sync_channel(1);
    let block = RcBlock::new(move |error: *mut NSError| {
        let r = if error.is_null() {
            Ok(())
        } else {
            Err(ns_error("startCapture", error))
        };
        let _ = tx.try_send(r);
    });
    // SAFETY : bloc retenu par le système pendant l'appel.
    unsafe { stream.startCaptureWithCompletionHandler(Some(&block)) };
    rx.recv_timeout(CALL_TIMEOUT)
        .map_err(|_| CaptureError::Backend("démarrage de la capture sans réponse".into()))??;

    Ok(Box::new(SckCapturer {
        display,
        frames,
        stream,
        _output: output,
        _queue: queue,
    }))
}

struct SckCapturer {
    display: DisplayInfo,
    frames: Receiver<Frame>,
    stream: Retained<SCStream>,
    _output: Retained<StreamOutput>,
    _queue: dispatch2::DispatchRetained<DispatchQueue>,
}

impl Capturer for SckCapturer {
    fn display(&self) -> &DisplayInfo {
        &self.display
    }

    fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame>> {
        match self.frames.recv_timeout(timeout) {
            Ok(mut f) => {
                // Ne garder que la plus récente si plusieurs attendent.
                while let Ok(newer) = self.frames.try_recv() {
                    f = newer;
                }
                Ok(Some(f))
            }
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => {
                Err(CaptureError::Backend("flux ScreenCaptureKit arrêté".into()))
            }
        }
    }
}

impl Drop for SckCapturer {
    fn drop(&mut self) {
        // SAFETY : arrêt asynchrone sans rappel.
        unsafe { self.stream.stopCaptureWithCompletionHandler(None) };
    }
}
