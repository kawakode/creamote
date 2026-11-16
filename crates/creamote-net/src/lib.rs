//! Transport réseau de Creamote.
//!
//! - [`tls`] : QUIC/TLS 1.3 avec épinglage du certificat du serveur (pas d'AC :
//!   un serveur auto-hébergé est identifié par son empreinte).
//! - [`frame`] : lecture/écriture de trames sur un flux.
//! - [`rendezvous`] : client du serveur de rendezvous (enregistrement prouvé,
//!   demande de session, offres entrantes).
//! - [`relay`] : connexion au relay avec le jeton délivré par le rendezvous.
//! - [`secure`] : canal chiffré de bout en bout (Noise XX) au-dessus de
//!   n'importe quel flux, typiquement un flux relay.

pub mod frame;
pub mod ident;
pub mod relay;
pub mod rendezvous;
pub mod secure;
pub mod tls;

pub use creamote_proto::rendezvous::v1::connect_rejected::Reason as RejectReason;
pub use creamote_proto::rendezvous::v1::register_peer_response::Status as RegisterStatus;

/// Nom de serveur TLS utilisé par tous les pairs (le certificat est épinglé,
/// le nom n'a donc pas de rôle de sécurité).
pub const SERVER_NAME: &str = "creamote";

/// Port par défaut du serveur (rendezvous et relay, UDP).
pub const DEFAULT_PORT: u16 = 21_400;

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("entrée/sortie : {0}")]
    Io(#[from] std::io::Error),
    #[error("connexion QUIC impossible : {0}")]
    Connect(#[from] quinn::ConnectError),
    #[error("connexion QUIC perdue : {0}")]
    Connection(#[from] quinn::ConnectionError),
    #[error("configuration TLS : {0}")]
    Tls(#[from] rustls::Error),
    #[error("trame invalide : {0}")]
    Frame(#[from] creamote_proto::framing::FrameError),
    #[error("cryptographie : {0}")]
    Crypto(#[from] creamote_crypto::CryptoError),
    #[error("enregistrement refusé par le serveur : {0:?}")]
    Registration(RegisterStatus),
    #[error("session refusée : {0:?}")]
    Rejected(RejectReason),
    #[error("protocole : {0}")]
    Protocol(&'static str),
    #[error("le flux a été fermé")]
    Closed,
}

pub type Result<T, E = NetError> = std::result::Result<T, E>;
