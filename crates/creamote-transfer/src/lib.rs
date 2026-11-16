//! Presse-papier partagé et transfert de fichiers dans une session Creamote.
//!
//! Les deux fonctions échangent des [`SessionMessage`] à l'intérieur du canal
//! chiffré de bout en bout, mêlés aux autres messages de la session (vidéo,
//! entrées). La boucle de session aiguille les messages reçus avec
//! [`route`] et envoie ceux que produisent [`clipboard::ClipboardSync`] et
//! [`files::FileTransfers`].
//!
//! Le host n'aiguille ces messages que si la session a obtenu la permission
//! correspondante (`clipboard`, `file_transfer`) : voir [`Route::permission`].

pub mod clipboard;
pub mod files;
pub mod paths;

use creamote_proto::session::v1::session_message::Kind;
use creamote_proto::session::v1::{ClipboardChunk, SessionMessage};

/// Destination d'un message reçu.
#[derive(Debug)]
pub enum Route {
    /// Morceau de presse-papier : [`clipboard::ClipboardSync::receive`].
    Clipboard(ClipboardChunk),
    /// Message de transfert de fichiers : [`files::FilesHandle::deliver`].
    File(SessionMessage),
    /// Autre message de session.
    Other(SessionMessage),
}

/// Permission qu'exige un message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Needs {
    Clipboard,
    FileTransfer,
}

impl Route {
    pub fn permission(&self) -> Option<Needs> {
        match self {
            Route::Clipboard(_) => Some(Needs::Clipboard),
            Route::File(_) => Some(Needs::FileTransfer),
            Route::Other(_) => None,
        }
    }
}

/// Aiguille un message reçu.
pub fn route(msg: SessionMessage) -> Route {
    match msg.kind {
        Some(Kind::ClipboardChunk(c)) => Route::Clipboard(c),
        Some(
            Kind::FileOffer(_)
            | Kind::FileAnswer(_)
            | Kind::FileChunk(_)
            | Kind::FileAck(_)
            | Kind::FileEnd(_)
            | Kind::FileCancel(_)
            | Kind::FileResult(_),
        ) => Route::File(msg),
        _ => Route::Other(msg),
    }
}

pub(crate) fn msg(kind: Kind) -> SessionMessage {
    SessionMessage { kind: Some(kind) }
}
