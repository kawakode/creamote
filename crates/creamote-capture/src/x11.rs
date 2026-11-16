//! Capture X11 : MIT-SHM (`ShmGetImage`) quand le serveur le permet, sinon
//! `GetImage` ; curseur incrusté via XFixes. X11 ne signale pas les
//! changements sans l'extension Damage : on compare avec l'image précédente.
#![allow(unsafe_code)]

use std::time::{Duration, Instant};

use x11rb::connection::Connection;
use x11rb::protocol::randr::ConnectionExt as _;
use x11rb::protocol::shm::ConnectionExt as _;
use x11rb::protocol::xfixes::ConnectionExt as _;
use x11rb::protocol::xproto::{ConnectionExt as _, ImageFormat, Window};
use x11rb::rust_connection::RustConnection;

use crate::{CaptureError, Capturer, DisplayInfo, Frame, Result};

/// Intervalle de scrutation quand l'écran ne change pas.
const POLL: Duration = Duration::from_millis(16);

fn err(e: impl std::fmt::Display) -> CaptureError {
    CaptureError::Backend(format!("X11 : {e}"))
}

pub fn init() {}

fn connect() -> Result<(RustConnection, Window)> {
    let (conn, screen) = x11rb::connect(None)
        .map_err(|e| CaptureError::Unsupported(format!("pas de serveur X11 ($DISPLAY) : {e}")))?;
    let root = conn.setup().roots[screen].root;
    Ok((conn, root))
}

pub fn displays() -> Result<Vec<DisplayInfo>> {
    let (conn, root) = connect()?;
    list(&conn, root)
}

fn list(conn: &RustConnection, root: Window) -> Result<Vec<DisplayInfo>> {
    let monitors = conn
        .randr_get_monitors(root, true)
        .ok()
        .and_then(|c| c.reply().ok())
        .map(|r| r.monitors)
        .unwrap_or_default();
    if monitors.is_empty() {
        // Pas de RandR (Xvfb ancien, serveurs exotiques) : l'écran entier.
        let g = conn.get_geometry(root).map_err(err)?.reply().map_err(err)?;
        return Ok(vec![DisplayInfo {
            id: 0,
            name: "X11".into(),
            x: 0,
            y: 0,
            width: g.width.into(),
            height: g.height.into(),
            scale: 1.0,
            primary: true,
        }]);
    }
    let any_primary = monitors.iter().any(|m| m.primary);
    Ok(monitors
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let name = conn
                .get_atom_name(m.name)
                .ok()
                .and_then(|c| c.reply().ok())
                .map(|r| String::from_utf8_lossy(&r.name).into_owned())
                .unwrap_or_else(|| format!("Écran {}", i + 1));
            DisplayInfo {
                id: i as u32,
                name,
                x: m.x.into(),
                y: m.y.into(),
                width: m.width.into(),
                height: m.height.into(),
                scale: 1.0,
                primary: m.primary || (!any_primary && i == 0),
            }
        })
        .collect())
}

pub fn open(display: DisplayInfo) -> Result<Box<dyn Capturer>> {
    let (conn, root) = connect()?;
    let shm = Shm::new(&conn, display.width as usize * display.height as usize * 4);
    if shm.is_none() {
        tracing::info!("MIT-SHM indisponible : capture X11 par GetImage");
    }
    let cursor = conn
        .xfixes_query_version(5, 0)
        .ok()
        .and_then(|c| c.reply().ok())
        .is_some();
    Ok(Box::new(X11Capturer {
        conn,
        root,
        display,
        shm,
        cursor,
        previous: Vec::new(),
    }))
}

struct X11Capturer {
    conn: RustConnection,
    root: Window,
    display: DisplayInfo,
    shm: Option<Shm>,
    cursor: bool,
    previous: Vec<u8>,
}

impl X11Capturer {
    fn grab(&mut self) -> Result<Vec<u8>> {
        let d = &self.display;
        let (x, y, w, h) = (d.x as i16, d.y as i16, d.width as u16, d.height as u16);
        let mut data = if let Some(shm) = &self.shm {
            let r = self
                .conn
                .shm_get_image(
                    self.root,
                    x,
                    y,
                    w,
                    h,
                    !0,
                    ImageFormat::Z_PIXMAP.into(),
                    shm.seg,
                    0,
                )
                .map_err(err)?
                .reply();
            match r {
                Ok(_) => shm.bytes().to_vec(),
                Err(e) => {
                    tracing::warn!("ShmGetImage : {e} ; repli sur GetImage");
                    self.shm = None;
                    return self.grab();
                }
            }
        } else {
            self.conn
                .get_image(ImageFormat::Z_PIXMAP, self.root, x, y, w, h, !0)
                .map_err(err)?
                .reply()
                .map_err(err)?
                .data
        };
        let expected = d.width as usize * d.height as usize * 4;
        if data.len() < expected {
            return Err(CaptureError::Unsupported(format!(
                "format X11 inattendu ({} octets pour {}×{}, profondeur 24/32 requise)",
                data.len(),
                d.width,
                d.height
            )));
        }
        data.truncate(expected);
        if self.cursor {
            self.draw_cursor(&mut data);
        }
        Ok(data)
    }

    fn draw_cursor(&self, data: &mut [u8]) {
        let Some(c) = self
            .conn
            .xfixes_get_cursor_image()
            .ok()
            .and_then(|c| c.reply().ok())
        else {
            return;
        };
        let d = &self.display;
        let ox = i32::from(c.x) - i32::from(c.xhot) - d.x;
        let oy = i32::from(c.y) - i32::from(c.yhot) - d.y;
        blend_argb(
            data,
            d.width,
            d.height,
            &c.cursor_image,
            c.width.into(),
            c.height.into(),
            ox,
            oy,
        );
    }
}

impl Capturer for X11Capturer {
    fn display(&self) -> &DisplayInfo {
        &self.display
    }

    fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame>> {
        let deadline = Instant::now() + timeout;
        loop {
            let captured_at = Instant::now();
            let data = self.grab()?;
            if data != self.previous {
                self.previous.clone_from(&data);
                return Ok(Some(Frame {
                    width: self.display.width,
                    height: self.display.height,
                    stride: self.display.width as usize * 4,
                    data,
                    captured_at,
                }));
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            std::thread::sleep(POLL.min(deadline - now));
        }
    }
}

/// Incruste une image ARGB prémultipliée (curseur XFixes) en (`ox`, `oy`).
#[allow(clippy::too_many_arguments)]
fn blend_argb(dst: &mut [u8], dw: u32, dh: u32, src: &[u32], sw: i32, sh: i32, ox: i32, oy: i32) {
    for sy in 0..sh {
        let y = oy + sy;
        if y < 0 || y >= dh as i32 {
            continue;
        }
        for sx in 0..sw {
            let x = ox + sx;
            if x < 0 || x >= dw as i32 {
                continue;
            }
            let p = src[(sy * sw + sx) as usize];
            let a = p >> 24;
            if a == 0 {
                continue;
            }
            let i = (y as usize * dw as usize + x as usize) * 4;
            for (k, shift) in [(0, 0), (1, 8), (2, 16)] {
                let s = (p >> shift) & 0xff;
                let d = u32::from(dst[i + k]);
                dst[i + k] = (s + d * (255 - a) / 255).min(255) as u8;
            }
        }
    }
}

/// Segment de mémoire partagée SysV attaché au serveur X.
struct Shm {
    seg: u32,
    addr: *mut libc::c_void,
    len: usize,
}

// Le segment n'est accédé que par le thread propriétaire du capteur.
unsafe impl Send for Shm {}

impl Shm {
    fn new(conn: &RustConnection, len: usize) -> Option<Self> {
        conn.shm_query_version().ok()?.reply().ok()?;
        // SAFETY : appels SysV standard ; chaque erreur est vérifiée et le
        // segment est marqué pour destruction dès qu'il est attaché.
        unsafe {
            let id = libc::shmget(libc::IPC_PRIVATE, len, libc::IPC_CREAT | 0o600);
            if id < 0 {
                return None;
            }
            let addr = libc::shmat(id, std::ptr::null(), 0);
            if addr as isize == -1 {
                libc::shmctl(id, libc::IPC_RMID, std::ptr::null_mut());
                return None;
            }
            let seg = conn.generate_id().ok()?;
            let ok = conn
                .shm_attach(seg, id as u32, false)
                .ok()
                .and_then(|c| c.check().ok())
                .is_some();
            libc::shmctl(id, libc::IPC_RMID, std::ptr::null_mut());
            if !ok {
                // Serveur distant (ssh -X) : pas de mémoire partagée.
                libc::shmdt(addr);
                return None;
            }
            Some(Self { seg, addr, len })
        }
    }

    fn bytes(&self) -> &[u8] {
        // SAFETY : `addr` pointe sur `len` octets attachés tant que `self` vit.
        unsafe { std::slice::from_raw_parts(self.addr as *const u8, self.len) }
    }
}

impl Drop for Shm {
    fn drop(&mut self) {
        // SAFETY : `addr` provient de `shmat`.
        unsafe {
            libc::shmdt(self.addr);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_blend_clips_and_composites() {
        let mut dst = vec![0u8; 2 * 2 * 4];
        // Pixel opaque rouge, pixel transparent.
        let src = [0xffff_0000u32, 0];
        blend_argb(&mut dst, 2, 2, &src, 2, 1, 1, 1);
        assert_eq!(&dst[12..16], &[0, 0, 0xff, 0]);
        assert!(dst[..12].iter().all(|&b| b == 0));
    }
}
