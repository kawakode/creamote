//! Cœur Rust de l'app Android Creamote, exposé à Kotlin par uniffi.
//!
//! L'app (`android/`) charge `libcreamote_mobile.so` et appelle cette API
//! depuis des threads d'arrière-plan : les fonctions qui touchent au réseau
//! sont bloquantes. Le runtime tokio est interne.
//!
//! - [`Identity`] : identité de l'appareil (Ed25519), stockée dans un
//!   fichier privé de l'app.
//! - [`connect`] : session viewer ; la vidéo H.264 est remise à l'app
//!   ([`ViewerListener::on_frame`]), qui la décode avec MediaCodec.
//! - [`start_host`] : host ; l'app capture et encode l'écran elle-même
//!   (MediaProjection → surface d'entrée MediaCodec) et pousse les images
//!   encodées ([`HostService::push_frame`]). Les entrées du viewer lui sont
//!   remises ([`HostDelegate::key`], [`HostDelegate::pointer`]) pour
//!   l'AccessibilityService ou une API constructeur.

use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};

use creamote_crypto::{DeviceIdentity, store};
use creamote_net::tls::ServerPin;

mod clipboard;
mod host;
mod keys;
mod logging;
mod viewer;

pub use clipboard::ClipboardProvider;
pub use host::{
    ConsentAnswer, ConsentRequest, EnrollmentInfo, HostConfig, HostDelegate, HostService,
    HostStatus, StreamInfo, StreamRequest, start_host,
};
pub use keys::{android_keycode, hid_from_android_keycode};
pub use logging::{LogSink, init_logging};
pub use viewer::{
    ConnectRequest, ConnectedInfo, VideoConfig, VideoFrame, ViewerListener, ViewerSession, connect,
};

uniffi::setup_scaffolding!();

/// Runtime partagé par toutes les sessions de l'app.
pub(crate) static RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("creamote-rt")
        .enable_all()
        .build()
        .expect("runtime tokio")
});

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MobileError {
    /// Saisie invalide (ID, empreinte, adresse).
    #[error("{detail}")]
    Invalid { detail: String },
    /// Serveur ou pair injoignable, connexion coupée.
    #[error("{detail}")]
    Network { detail: String },
    /// Refus : serveur, ticket, host ou utilisateur.
    #[error("{detail}")]
    Refused { detail: String },
    /// Erreur de l'app (MediaProjection refusée, encodeur indisponible).
    #[error("{detail}")]
    App { detail: String },
}

impl MobileError {
    pub(crate) fn invalid(m: impl std::fmt::Display) -> Self {
        Self::Invalid {
            detail: m.to_string(),
        }
    }
    pub(crate) fn network(m: impl std::fmt::Display) -> Self {
        Self::Network {
            detail: m.to_string(),
        }
    }
    pub(crate) fn refused(m: impl std::fmt::Display) -> Self {
        Self::Refused {
            detail: m.to_string(),
        }
    }
}

/// Exception inattendue levée par un rappel Kotlin.
impl From<uniffi::UnexpectedUniFFICallbackError> for MobileError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::App { detail: e.reason }
    }
}

/// Identité de l'appareil.
#[derive(uniffi::Object)]
pub struct Identity {
    pub(crate) inner: Arc<DeviceIdentity>,
}

#[uniffi::export]
impl Identity {
    /// Charge l'identité depuis `path`, ou la crée (fichier 0600).
    #[uniffi::constructor]
    pub fn load_or_create(path: String) -> Result<Arc<Self>, MobileError> {
        let (identity, _) =
            store::load_or_create(std::path::Path::new(&path)).map_err(|e| MobileError::App {
                detail: format!("identité {path} : {e}"),
            })?;
        Ok(Arc::new(Self {
            inner: Arc::new(identity),
        }))
    }

    /// ID à 9 chiffres communiqué aux autres appareils.
    pub fn device_id(&self) -> String {
        self.inner.device_id().to_string()
    }

    pub fn fingerprint(&self) -> String {
        self.inner.public().fingerprint()
    }
}

/// Serveur Creamote choisi par l'utilisateur.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ServerConfig {
    /// `hôte:port`.
    pub address: String,
    /// Empreinte du serveur (affichée au démarrage de creamote-server).
    pub pin: String,
}

impl ServerConfig {
    pub(crate) fn pin(&self) -> Result<ServerPin, MobileError> {
        self.pin
            .trim()
            .parse()
            .map_err(|e| MobileError::invalid(format!("empreinte du serveur invalide : {e}")))
    }

    pub(crate) async fn resolve(&self) -> Result<SocketAddr, MobileError> {
        let address = self.address.trim();
        tokio::net::lookup_host(address)
            .await
            .ok()
            .and_then(|mut a| a.next())
            .ok_or_else(|| MobileError::network(format!("adresse introuvable : {address}")))
    }
}

/// Écran du host.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct Display {
    pub id: u32,
    pub name: String,
    pub width: u32,
    pub height: u32,
    pub primary: bool,
}

impl From<&creamote_proto::session::v1::Display> for Display {
    fn from(d: &creamote_proto::session::v1::Display) -> Self {
        Self {
            id: d.id,
            name: d.name.clone(),
            width: d.width,
            height: d.height,
            primary: d.primary,
        }
    }
}

/// Version du cœur (affichée dans l'app).
#[uniffi::export]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
