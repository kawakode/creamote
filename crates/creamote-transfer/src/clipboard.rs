//! Presse-papier partagé.
//!
//! - [`encode`] / [`Reassembler`] : découpage d'une copie en
//!   [`ClipboardChunk`] et reconstitution, avec limites de taille.
//! - [`ClipboardBackend`] : accès au presse-papier de l'OS ;
//!   [`NativeClipboard`] utilise les API natives (Win32, NSPasteboard,
//!   sélections X11, data-control Wayland) via `arboard`.
//! - [`ClipboardSync`] : surveille les copies locales et applique celles du
//!   pair, sans renvoyer au pair ce qu'il vient d'envoyer.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use creamote_proto::session::v1::session_message::Kind;
use creamote_proto::session::v1::{ClipboardChunk, ClipboardFormat, SessionMessage};
use tokio::sync::mpsc;

/// Taille maximale d'un format, en octets.
pub const MAX_FORMAT_SIZE: usize = 16 * 1024 * 1024;
/// Taille des morceaux (un message chiffré fait au plus 64 Kio).
pub const CHUNK_SIZE: usize = 48 * 1024;
/// Intervalle de surveillance du presse-papier local.
pub const POLL_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Debug, thiserror::Error)]
pub enum ClipboardError {
    #[error("presse-papier de l'OS : {0}")]
    Os(String),
    #[error("contenu trop volumineux")]
    TooLarge,
    #[error("morceau incohérent")]
    BadChunk,
    #[error("texte non UTF-8")]
    BadText,
    #[error("image : {0}")]
    Image(String),
}

/// Contenu d'une copie. Plusieurs formats peuvent coexister (texte + HTML).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClipboardContent {
    pub text: Option<String>,
    pub html: Option<String>,
    /// Image encodée en PNG.
    pub png: Option<Vec<u8>>,
}

impl ClipboardContent {
    pub fn is_empty(&self) -> bool {
        self.text.is_none() && self.html.is_none() && self.png.is_none()
    }

    /// Empreinte du contenu, pour détecter les changements.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        for (tag, part) in self.parts() {
            h.update(&[tag as u8]);
            h.update(&(part.len() as u64).to_le_bytes());
            h.update(part);
        }
        *h.finalize().as_bytes()
    }

    fn parts(&self) -> Vec<(ClipboardFormat, &[u8])> {
        let mut out = Vec::new();
        if let Some(t) = &self.text {
            out.push((ClipboardFormat::Text, t.as_bytes()));
        }
        if let Some(h) = &self.html {
            out.push((ClipboardFormat::Html, h.as_bytes()));
        }
        if let Some(p) = &self.png {
            out.push((ClipboardFormat::Png, p.as_slice()));
        }
        out
    }
}

/// Découpe une copie en messages. Les formats au-delà de
/// [`MAX_FORMAT_SIZE`] sont omis ; `None` si rien ne reste.
pub fn encode(sequence: u64, content: &ClipboardContent) -> Option<Vec<SessionMessage>> {
    let parts: Vec<_> = content
        .parts()
        .into_iter()
        .filter(|(_, p)| p.len() <= MAX_FORMAT_SIZE)
        .collect();
    if parts.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    let last_part = parts.len() - 1;
    for (i, (format, data)) in parts.into_iter().enumerate() {
        let total = data.len() as u64;
        let mut chunks: Vec<&[u8]> = data.chunks(CHUNK_SIZE).collect();
        if chunks.is_empty() {
            chunks.push(&[]);
        }
        let last_chunk = chunks.len() - 1;
        let mut offset = 0u64;
        for (j, c) in chunks.into_iter().enumerate() {
            out.push(crate::msg(Kind::ClipboardChunk(ClipboardChunk {
                sequence,
                format: format as i32,
                total_size: total,
                offset,
                data: c.to_vec(),
                end_of_update: i == last_part && j == last_chunk,
            })));
            offset += c.len() as u64;
        }
    }
    Some(out)
}

/// Reconstitue les copies reçues.
#[derive(Default)]
pub struct Reassembler {
    sequence: Option<u64>,
    done: ClipboardContent,
    current: Option<(ClipboardFormat, usize, Vec<u8>)>,
    broken: bool,
}

impl Reassembler {
    /// Ajoute un morceau ; renvoie la copie quand elle est complète. Une
    /// nouvelle séquence abandonne la copie en cours.
    pub fn push(
        &mut self,
        chunk: ClipboardChunk,
    ) -> Result<Option<ClipboardContent>, ClipboardError> {
        if self.sequence != Some(chunk.sequence) {
            *self = Self {
                sequence: Some(chunk.sequence),
                ..Self::default()
            };
        }
        if self.broken {
            return Ok(None);
        }
        let result = self.push_inner(chunk);
        if result.is_err() {
            self.broken = true;
            self.current = None;
        }
        result
    }

    fn push_inner(
        &mut self,
        chunk: ClipboardChunk,
    ) -> Result<Option<ClipboardContent>, ClipboardError> {
        let format =
            ClipboardFormat::try_from(chunk.format).map_err(|_| ClipboardError::BadChunk)?;
        let total = usize::try_from(chunk.total_size).map_err(|_| ClipboardError::TooLarge)?;
        if total > MAX_FORMAT_SIZE {
            return Err(ClipboardError::TooLarge);
        }
        let (cur_format, cur_total, buf) = self
            .current
            .get_or_insert_with(|| (format, total, Vec::with_capacity(total.min(CHUNK_SIZE * 4))));
        if *cur_format != format
            || *cur_total != total
            || chunk.offset != buf.len() as u64
            || buf.len() + chunk.data.len() > total
        {
            return Err(ClipboardError::BadChunk);
        }
        buf.extend_from_slice(&chunk.data);
        if buf.len() == total {
            let (format, _, data) = self.current.take().expect("présent");
            let text = || String::from_utf8(data.clone()).map_err(|_| ClipboardError::BadText);
            match format {
                ClipboardFormat::Text => self.done.text = Some(text()?),
                ClipboardFormat::Html => self.done.html = Some(text()?),
                ClipboardFormat::Png => self.done.png = Some(data),
                ClipboardFormat::Unspecified => return Err(ClipboardError::BadChunk),
            }
        }
        if chunk.end_of_update {
            if self.current.is_some() {
                return Err(ClipboardError::BadChunk);
            }
            self.sequence = None;
            return Ok(Some(std::mem::take(&mut self.done)));
        }
        Ok(None)
    }
}

/// Accès au presse-papier de l'OS. Les appels sont bloquants : ils sont
/// faits hors du runtime asynchrone.
pub trait ClipboardBackend: Send + 'static {
    fn read(&mut self) -> Result<ClipboardContent, ClipboardError>;
    fn write(&mut self, content: &ClipboardContent) -> Result<(), ClipboardError>;
    /// Compteur de changements fourni par l'OS, s'il existe : permet de ne
    /// relire le contenu qu'après une copie.
    fn change_count(&mut self) -> Option<u64> {
        None
    }
}

/// Presse-papier de l'OS via `arboard` (API natives).
pub struct NativeClipboard {
    inner: arboard::Clipboard,
    /// Dernière image lue (empreinte des pixels, PNG) : évite de réencoder
    /// la même image à chaque lecture.
    image_cache: Option<([u8; 32], Vec<u8>)>,
}

impl NativeClipboard {
    pub fn new() -> Result<Self, ClipboardError> {
        Ok(Self {
            inner: arboard::Clipboard::new().map_err(os)?,
            image_cache: None,
        })
    }
}

fn os(e: arboard::Error) -> ClipboardError {
    ClipboardError::Os(e.to_string())
}

/// `Ok(None)` quand le format est simplement absent.
fn optional<T>(r: Result<T, arboard::Error>) -> Result<Option<T>, ClipboardError> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(arboard::Error::ContentNotAvailable | arboard::Error::ConversionFailure) => Ok(None),
        Err(e) => Err(os(e)),
    }
}

impl ClipboardBackend for NativeClipboard {
    fn read(&mut self) -> Result<ClipboardContent, ClipboardError> {
        let text = optional(self.inner.get_text())?;
        let html = optional(self.inner.get().html())?;
        // Une image n'est lue qu'en l'absence de texte (une copie depuis un
        // traitement de texte porte souvent les deux).
        let png = if text.is_none() {
            match optional(self.inner.get_image())? {
                Some(img) => {
                    let key = *blake3::hash(&img.bytes).as_bytes();
                    match &self.image_cache {
                        Some((k, png)) if *k == key => Some(png.clone()),
                        _ => {
                            let png = encode_png(img.width, img.height, &img.bytes)?;
                            self.image_cache = Some((key, png.clone()));
                            Some(png)
                        }
                    }
                }
                None => None,
            }
        } else {
            None
        };
        Ok(ClipboardContent { text, html, png })
    }

    fn write(&mut self, content: &ClipboardContent) -> Result<(), ClipboardError> {
        if let Some(html) = &content.html {
            self.inner
                .set_html(html.as_str(), content.text.as_deref())
                .map_err(os)
        } else if let Some(text) = &content.text {
            self.inner.set_text(text.as_str()).map_err(os)
        } else if let Some(png) = &content.png {
            let (width, height, rgba) = decode_png(png)?;
            self.inner
                .set_image(arboard::ImageData {
                    width,
                    height,
                    bytes: rgba.into(),
                })
                .map_err(os)
        } else {
            Ok(())
        }
    }

    fn change_count(&mut self) -> Option<u64> {
        #[cfg(windows)]
        {
            clipboard_win::seq_num().map(|n| u64::from(n.get()))
        }
        #[cfg(not(windows))]
        {
            None
        }
    }
}

/// Encode des pixels RGBA 8 bits en PNG.
pub fn encode_png(width: usize, height: usize, rgba: &[u8]) -> Result<Vec<u8>, ClipboardError> {
    let img = |e: png::EncodingError| ClipboardError::Image(e.to_string());
    if width.checked_mul(height).and_then(|n| n.checked_mul(4)) != Some(rgba.len()) {
        return Err(ClipboardError::Image("dimensions incohérentes".into()));
    }
    let mut out = Vec::new();
    let mut enc = png::Encoder::new(
        &mut out,
        u32::try_from(width).map_err(|_| ClipboardError::TooLarge)?,
        u32::try_from(height).map_err(|_| ClipboardError::TooLarge)?,
    );
    enc.set_color(png::ColorType::Rgba);
    enc.set_depth(png::BitDepth::Eight);
    enc.set_compression(png::Compression::Fast);
    let mut w = enc.write_header().map_err(img)?;
    w.write_image_data(rgba).map_err(img)?;
    w.finish().map_err(img)?;
    Ok(out)
}

/// Décode un PNG reçu en pixels RGBA 8 bits (taille bornée).
pub fn decode_png(data: &[u8]) -> Result<(usize, usize, Vec<u8>), ClipboardError> {
    let img = |e: png::DecodingError| ClipboardError::Image(e.to_string());
    let mut dec = png::Decoder::new(std::io::Cursor::new(data));
    dec.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = dec.read_info().map_err(img)?;
    let info = reader.info();
    let (w, h) = (info.width as usize, info.height as usize);
    // Borne la mémoire allouée pour une image reçue (64 Mpx).
    if w.saturating_mul(h) > 64 * 1024 * 1024 {
        return Err(ClipboardError::TooLarge);
    }
    let size = reader
        .output_buffer_size()
        .ok_or(ClipboardError::TooLarge)?;
    let mut buf = vec![0u8; size];
    let frame = reader.next_frame(&mut buf).map_err(img)?;
    buf.truncate(frame.buffer_size());
    let rgba = match frame.color_type {
        png::ColorType::Rgba => buf,
        png::ColorType::Rgb => buf
            .chunks_exact(3)
            .flat_map(|p| [p[0], p[1], p[2], 255])
            .collect(),
        png::ColorType::GrayscaleAlpha => buf
            .chunks_exact(2)
            .flat_map(|p| [p[0], p[0], p[0], p[1]])
            .collect(),
        png::ColorType::Grayscale => buf.iter().flat_map(|&g| [g, g, g, 255]).collect(),
        png::ColorType::Indexed => {
            return Err(ClipboardError::Image("palette non développée".into()));
        }
    };
    Ok((w, h, rgba))
}

/// Synchronisation du presse-papier avec le pair.
pub struct ClipboardSync {
    backend: Arc<Mutex<Box<dyn ClipboardBackend>>>,
    /// Empreinte du dernier contenu envoyé ou appliqué : ni renvoyé, ni
    /// réappliqué.
    last: Arc<Mutex<Option<[u8; 32]>>>,
    reassembler: Reassembler,
}

impl ClipboardSync {
    pub fn new(backend: Box<dyn ClipboardBackend>) -> Self {
        Self {
            backend: Arc::new(Mutex::new(backend)),
            last: Arc::new(Mutex::new(None)),
            reassembler: Reassembler::default(),
        }
    }

    /// Surveille le presse-papier local et produit les messages à envoyer
    /// au pair à chaque copie. Le contenu présent au démarrage n'est pas
    /// envoyé. S'arrête quand le récepteur est abandonné.
    pub fn watch(&self, interval: Duration) -> mpsc::Receiver<Vec<SessionMessage>> {
        let (tx, rx) = mpsc::channel(4);
        let (backend, last) = (self.backend.clone(), self.last.clone());
        tokio::task::spawn_blocking(move || {
            let mut sequence = 0u64;
            let mut count: Option<u64> = None;
            let mut first = true;
            while !tx.is_closed() {
                if !first {
                    std::thread::sleep(interval);
                }
                let content = {
                    let mut b = backend.lock().expect("verrou sain");
                    let c = b.change_count();
                    if c.is_some() && c == count {
                        continue;
                    }
                    count = c;
                    match b.read() {
                        Ok(content) => content,
                        Err(e) => {
                            tracing::debug!("lecture du presse-papier : {e}");
                            continue;
                        }
                    }
                };
                if content.is_empty() {
                    first = false;
                    continue;
                }
                let digest = content.digest();
                {
                    let mut last = last.lock().expect("verrou sain");
                    if *last == Some(digest) {
                        first = false;
                        continue;
                    }
                    *last = Some(digest);
                }
                if std::mem::take(&mut first) {
                    continue;
                }
                sequence += 1;
                if let Some(msgs) = encode(sequence, &content) {
                    if tx.blocking_send(msgs).is_err() {
                        break;
                    }
                }
            }
        });
        rx
    }

    /// Traite un morceau reçu ; applique la copie au presse-papier local
    /// quand elle est complète (renvoie `true`).
    pub async fn receive(&mut self, chunk: ClipboardChunk) -> Result<bool, ClipboardError> {
        let Some(content) = self.reassembler.push(chunk)? else {
            return Ok(false);
        };
        if content.is_empty() {
            return Ok(false);
        }
        *self.last.lock().expect("verrou sain") = Some(content.digest());
        let backend = self.backend.clone();
        tokio::task::spawn_blocking(move || backend.lock().expect("verrou sain").write(&content))
            .await
            .map_err(|e| ClipboardError::Os(e.to_string()))??;
        Ok(true)
    }
}

/// Presse-papier en mémoire (tests, ou session sans accès à l'OS).
#[derive(Clone, Default)]
pub struct MemoryClipboard(pub Arc<Mutex<ClipboardContent>>);

impl ClipboardBackend for MemoryClipboard {
    fn read(&mut self) -> Result<ClipboardContent, ClipboardError> {
        Ok(self.0.lock().expect("verrou sain").clone())
    }

    fn write(&mut self, content: &ClipboardContent) -> Result<(), ClipboardError> {
        *self.0.lock().expect("verrou sain") = content.clone();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunks(msgs: Vec<SessionMessage>) -> Vec<ClipboardChunk> {
        msgs.into_iter()
            .map(|m| match m.kind {
                Some(Kind::ClipboardChunk(c)) => c,
                _ => panic!("morceau attendu"),
            })
            .collect()
    }

    #[test]
    fn roundtrip_multi_format_and_large() {
        let content = ClipboardContent {
            text: Some("é".repeat(100_000)),
            html: Some("<b>gras</b>".into()),
            png: Some(vec![9u8; 3 * CHUNK_SIZE + 5]),
        };
        let parts = chunks(encode(7, &content).unwrap());
        assert!(parts.len() > 6);
        assert_eq!(parts.iter().filter(|c| c.end_of_update).count(), 1);
        let mut r = Reassembler::default();
        let mut got = None;
        for c in parts {
            got = r.push(c).unwrap().or(got);
        }
        assert_eq!(got.unwrap(), content);
    }

    #[test]
    fn empty_text_is_transmitted() {
        let content = ClipboardContent {
            text: Some(String::new()),
            ..Default::default()
        };
        let mut r = Reassembler::default();
        let parts = chunks(encode(1, &content).unwrap());
        assert_eq!(parts.len(), 1);
        assert_eq!(r.push(parts[0].clone()).unwrap().unwrap(), content);
    }

    #[test]
    fn rejects_inconsistent_or_oversized_chunks() {
        let mut r = Reassembler::default();
        let bad = ClipboardChunk {
            sequence: 1,
            format: ClipboardFormat::Text as i32,
            total_size: 4,
            offset: 2,
            data: b"ab".to_vec(),
            end_of_update: true,
        };
        assert!(r.push(bad).is_err());
        let huge = ClipboardChunk {
            sequence: 2,
            format: ClipboardFormat::Png as i32,
            total_size: MAX_FORMAT_SIZE as u64 + 1,
            offset: 0,
            data: vec![],
            end_of_update: false,
        };
        assert!(matches!(r.push(huge), Err(ClipboardError::TooLarge)));
        let not_utf8 = ClipboardChunk {
            sequence: 3,
            format: ClipboardFormat::Text as i32,
            total_size: 1,
            offset: 0,
            data: vec![0xff],
            end_of_update: true,
        };
        assert!(matches!(r.push(not_utf8), Err(ClipboardError::BadText)));
    }

    #[test]
    fn new_sequence_discards_partial_update() {
        let a = ClipboardContent {
            text: Some("x".repeat(CHUNK_SIZE * 2)),
            ..Default::default()
        };
        let b = ClipboardContent {
            text: Some("b".into()),
            ..Default::default()
        };
        let mut r = Reassembler::default();
        let first = chunks(encode(1, &a).unwrap());
        assert!(r.push(first[0].clone()).unwrap().is_none());
        let second = chunks(encode(2, &b).unwrap());
        assert_eq!(r.push(second[0].clone()).unwrap().unwrap(), b);
    }

    #[test]
    fn png_roundtrip() {
        let rgba: Vec<u8> = (0..4 * 3 * 2).map(|i| i as u8).collect();
        let png = encode_png(3, 2, &rgba).unwrap();
        assert_eq!(decode_png(&png).unwrap(), (3, 2, rgba));
        assert!(encode_png(3, 3, &[0; 4]).is_err());
    }

    #[tokio::test]
    async fn sync_sends_local_copies_and_applies_remote_ones_without_echo() {
        let local = MemoryClipboard::default();
        *local.0.lock().unwrap() = ClipboardContent {
            text: Some("déjà là".into()),
            ..Default::default()
        };
        let mut sync = ClipboardSync::new(Box::new(local.clone()));
        let mut out = sync.watch(Duration::from_millis(10));
        tokio::time::sleep(Duration::from_millis(50)).await;
        // Le contenu initial n'est pas envoyé.
        assert!(out.try_recv().is_err());

        // Copie locale : envoyée.
        local.0.lock().unwrap().text = Some("copié".into());
        let msgs = tokio::time::timeout(Duration::from_secs(2), out.recv())
            .await
            .unwrap()
            .unwrap();
        let mut r = Reassembler::default();
        let mut got = None;
        for c in chunks(msgs) {
            got = r.push(c).unwrap().or(got);
        }
        assert_eq!(got.unwrap().text.as_deref(), Some("copié"));

        // Copie du pair : appliquée, mais pas renvoyée.
        let remote = ClipboardContent {
            text: Some("du pair".into()),
            ..Default::default()
        };
        for c in chunks(encode(1, &remote).unwrap()) {
            sync.receive(c).await.unwrap();
        }
        assert_eq!(*local.0.lock().unwrap(), remote);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(out.try_recv().is_err());
    }
}
