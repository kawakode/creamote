//! Réception d'un flux d'écran PipeWire (nœud fourni par le portail), en
//! mémoire partagée, au format BGRx/BGRA (RGBx/RGBA convertis).

use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use pipewire as pw;
use pw::properties::properties;
use pw::spa;
use pw::spa::param::video::{VideoFormat, VideoInfoRaw};
use pw::spa::pod::Pod;
use pw::stream::{StreamFlags, StreamState};

use super::portal::PortalSession;
use crate::{CaptureError, Capturer, DisplayInfo, Frame, Result};

fn err(e: impl std::fmt::Display) -> CaptureError {
    CaptureError::Backend(format!("PipeWire : {e}"))
}

enum Msg {
    Frame(Frame),
    Error(String),
}

pub struct PwCapturer {
    display: DisplayInfo,
    session: Arc<PortalSession>,
    frames: Receiver<Msg>,
    quit: pw::channel::Sender<()>,
    thread: Option<JoinHandle<()>>,
}

impl PwCapturer {
    pub fn open(session: Arc<PortalSession>, display: DisplayInfo) -> Result<Self> {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(pw::init);
        let fd = session.pipewire_fd()?;
        let node = display.id;
        let (tx, frames) = sync_channel(2);
        let (quit, quit_rx) = pw::channel::channel();
        let (ready_tx, ready) = std::sync::mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("creamote-pipewire".into())
            .spawn(move || {
                if let Err(e) = run(fd, node, &tx, quit_rx, &ready_tx) {
                    let _ = ready_tx.send(Err(e.to_string()));
                    let _ = tx.send(Msg::Error(e.to_string()));
                }
            })
            .map_err(err)?;
        match ready.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(err(e)),
            Err(_) => return Err(err("flux non connecté")),
        }
        Ok(Self {
            display,
            session,
            frames,
            quit,
            thread: Some(thread),
        })
    }
}

impl Capturer for PwCapturer {
    fn display(&self) -> &DisplayInfo {
        &self.display
    }

    fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame>> {
        // Ne garder que l'image la plus récente.
        let mut last = None;
        loop {
            let msg = match last {
                None => match self.frames.recv_timeout(timeout) {
                    Ok(m) => m,
                    Err(RecvTimeoutError::Timeout) => return Ok(None),
                    Err(RecvTimeoutError::Disconnected) => {
                        self.session.mark_closed();
                        return Err(err("flux terminé"));
                    }
                },
                Some(_) => match self.frames.try_recv() {
                    Ok(m) => m,
                    Err(_) => return Ok(last),
                },
            };
            match msg {
                Msg::Frame(f) => last = Some(f),
                Msg::Error(e) => {
                    // Partage révoqué ou portail redémarré.
                    self.session.mark_closed();
                    return Err(err(e));
                }
            }
        }
    }
}

impl Drop for PwCapturer {
    fn drop(&mut self) {
        let _ = self.quit.send(());
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

#[derive(Default)]
struct State {
    format: VideoInfoRaw,
    swap: bool,
}

fn run(
    fd: std::os::fd::OwnedFd,
    node: u32,
    tx: &SyncSender<Msg>,
    quit: pw::channel::Receiver<()>,
    ready: &std::sync::mpsc::Sender<Result<(), String>>,
) -> Result<(), pw::Error> {
    let mainloop = pw::main_loop::MainLoopRc::new(None)?;
    let context = pw::context::ContextRc::new(&mainloop, None)?;
    let core = context.connect_fd_rc(fd, None)?;
    let stream = pw::stream::StreamBox::new(
        &core,
        "creamote-capture",
        properties! {
            *pw::keys::MEDIA_TYPE => "Video",
            *pw::keys::MEDIA_CATEGORY => "Capture",
            *pw::keys::MEDIA_ROLE => "Screen",
        },
    )?;

    let ml = mainloop.clone();
    let _quit = quit.attach(mainloop.loop_(), move |()| ml.quit());
    let tx_state = tx.clone();
    let ml = mainloop.clone();
    let tx_frames = tx.clone();
    let _listener = stream
        .add_local_listener_with_user_data(State::default())
        .state_changed(move |_, _, _, new| {
            let e = match new {
                StreamState::Error(e) => e,
                StreamState::Unconnected => "flux déconnecté".into(),
                _ => return,
            };
            let _ = tx_state.send(Msg::Error(e));
            ml.quit();
        })
        .param_changed(|_, st, id, param| {
            let Some(param) = param else { return };
            if id != spa::param::ParamType::Format.as_raw() {
                return;
            }
            if st.format.parse(param).is_ok() {
                st.swap = matches!(st.format.format(), VideoFormat::RGBx | VideoFormat::RGBA);
                tracing::debug!(
                    "PipeWire : {:?} {}×{}",
                    st.format.format(),
                    st.format.size().width,
                    st.format.size().height
                );
            }
        })
        .process(move |stream, st| {
            let Some(mut buffer) = stream.dequeue_buffer() else {
                return;
            };
            let (w, h) = (st.format.size().width, st.format.size().height);
            let datas = buffer.datas_mut();
            let Some(d) = datas.first_mut() else { return };
            let chunk = d.chunk();
            let (offset, size) = (chunk.offset() as usize, chunk.size() as usize);
            let stride = match chunk.stride() {
                s if s > 0 => s as usize,
                _ => w as usize * 4,
            };
            let Some(mem) = d.data() else { return };
            let row = w as usize * 4;
            // Tampon vide (curseur seul, image inchangée) ou incomplet.
            if w == 0 || h == 0 || stride < row {
                return;
            }
            let needed = stride * (h as usize - 1) + row;
            if size < needed {
                return;
            }
            let Some(src) = mem.get(offset..offset + needed) else {
                return;
            };
            let mut data = crate::copy_rows(src, stride, w, h);
            if st.swap {
                for px in data.chunks_exact_mut(4) {
                    px.swap(0, 2);
                }
            }
            let frame = Frame {
                width: w,
                height: h,
                stride: row,
                data,
                captured_at: Instant::now(),
            };
            if let Err(TrySendError::Disconnected(_)) = tx_frames.try_send(Msg::Frame(frame)) {
                // Capteur fermé : la boucle s'arrête via `quit`.
            }
        })
        .register()?;

    let format = format_pod();
    let mut params = [Pod::from_bytes(&format).ok_or(pw::Error::CreationFailed)?];
    stream.connect(
        spa::utils::Direction::Input,
        Some(node),
        StreamFlags::AUTOCONNECT | StreamFlags::MAP_BUFFERS,
        &mut params,
    )?;
    let _ = ready.send(Ok(()));
    mainloop.run();
    let _ = stream.disconnect();
    Ok(())
}

/// Formats acceptés : 32 bits par pixel, mémoire partagée (pas de
/// modificateurs DMA-BUF annoncés), toute taille et cadence.
fn format_pod() -> Vec<u8> {
    use spa::param::format::{FormatProperties, MediaSubtype, MediaType};
    let obj = spa::pod::object!(
        spa::utils::SpaTypes::ObjectParamFormat,
        spa::param::ParamType::EnumFormat,
        spa::pod::property!(FormatProperties::MediaType, Id, MediaType::Video),
        spa::pod::property!(FormatProperties::MediaSubtype, Id, MediaSubtype::Raw),
        spa::pod::property!(
            FormatProperties::VideoFormat,
            Choice,
            Enum,
            Id,
            VideoFormat::BGRx,
            VideoFormat::BGRx,
            VideoFormat::BGRA,
            VideoFormat::RGBx,
            VideoFormat::RGBA,
        ),
        spa::pod::property!(
            FormatProperties::VideoSize,
            Choice,
            Range,
            Rectangle,
            spa::utils::Rectangle {
                width: 1920,
                height: 1080
            },
            spa::utils::Rectangle {
                width: 1,
                height: 1
            },
            spa::utils::Rectangle {
                width: 16384,
                height: 16384
            }
        ),
        spa::pod::property!(
            FormatProperties::VideoFramerate,
            Choice,
            Range,
            Fraction,
            spa::utils::Fraction { num: 60, denom: 1 },
            spa::utils::Fraction { num: 0, denom: 1 },
            spa::utils::Fraction { num: 240, denom: 1 }
        ),
    );
    spa::pod::serialize::PodSerializer::serialize(
        std::io::Cursor::new(Vec::new()),
        &spa::pod::Value::Object(obj),
    )
    .map(|(c, _)| c.into_inner())
    .unwrap_or_default()
}
