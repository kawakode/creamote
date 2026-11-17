//! Presse-papier de l'app (texte), via `ClipboardManager` côté Kotlin.

use std::sync::Arc;

use creamote_session::creamote_transfer::clipboard::{
    ClipboardBackend, ClipboardContent, ClipboardError,
};

/// Accès au presse-papier Android. Depuis Android 10, seule l'app au
/// premier plan peut le lire : `read_text` rend alors `None`.
#[uniffi::export(with_foreign)]
pub trait ClipboardProvider: Send + Sync {
    fn read_text(&self) -> Option<String>;
    fn write_text(&self, text: String);
}

pub(crate) struct AppClipboard(pub(crate) Arc<dyn ClipboardProvider>);

impl ClipboardBackend for AppClipboard {
    fn read(&mut self) -> Result<ClipboardContent, ClipboardError> {
        Ok(ClipboardContent {
            text: self.0.read_text().filter(|t| !t.is_empty()),
            html: None,
            png: None,
        })
    }

    fn write(&mut self, content: &ClipboardContent) -> Result<(), ClipboardError> {
        // Texte seulement ; une copie HTML porte en général aussi le texte.
        if let Some(text) = &content.text {
            self.0.write_text(text.clone());
        }
        Ok(())
    }
}
