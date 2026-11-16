//! Journal du cœur Rust renvoyé vers logcat (`android.util.Log`) par l'app.

use std::io::Write;
use std::sync::{Arc, OnceLock};

use tracing_subscriber::fmt::MakeWriter;

/// Reçoit chaque ligne du journal ; `level` : 0 trace … 4 erreur.
#[uniffi::export(with_foreign)]
pub trait LogSink: Send + Sync {
    fn log(&self, level: u8, message: String);
}

static SINK: OnceLock<Arc<dyn LogSink>> = OnceLock::new();

/// Installe le journal (une seule fois par processus ; les appels suivants
/// sont ignorés). `filter` : syntaxe `RUST_LOG`, ex. `info,creamote_net=debug`.
#[uniffi::export]
pub fn init_logging(sink: Arc<dyn LogSink>, filter: String) {
    if SINK.set(sink).is_err() {
        return;
    }
    let filter = tracing_subscriber::EnvFilter::try_new(&filter)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .without_time()
        .with_writer(Writers)
        .try_init();
}

struct Writers;

impl<'a> MakeWriter<'a> for Writers {
    type Writer = Line;

    fn make_writer(&'a self) -> Line {
        Line {
            level: 2,
            buf: Vec::new(),
        }
    }

    fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Line {
        let level = match *meta.level() {
            tracing::Level::TRACE => 0,
            tracing::Level::DEBUG => 1,
            tracing::Level::INFO => 2,
            tracing::Level::WARN => 3,
            tracing::Level::ERROR => 4,
        };
        Line {
            level,
            buf: Vec::new(),
        }
    }
}

/// Une entrée du journal, envoyée à l'app quand elle est complète.
struct Line {
    level: u8,
    buf: Vec<u8>,
}

impl Write for Line {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for Line {
    fn drop(&mut self) {
        if let Some(sink) = SINK.get() {
            let msg = String::from_utf8_lossy(&self.buf).trim_end().to_string();
            if !msg.is_empty() {
                sink.log(self.level, msg);
            }
        }
    }
}
