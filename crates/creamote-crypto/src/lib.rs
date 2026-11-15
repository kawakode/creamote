//! Cryptographie de Creamote.
//!
//! - [`identity`] : identité longue durée d'un appareil (Ed25519) liée à sa clé
//!   statique Noise (X25519), ID à 9 chiffres et empreinte.
//! - [`noise`] : handshake Noise XX authentifié par ces identités, puis canal
//!   chiffré de bout en bout. Le relay ne transporte que des octets opaques.

pub mod identity;
pub mod noise;
pub mod store;

pub use identity::{DeviceId, DeviceIdentity, PublicIdentity};
pub use noise::{Initiator, Responder, ResponderAwaitingFinish, SecureSession};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("données d'identité invalides")]
    InvalidIdentity,
    #[error("signature de liaison Noise invalide")]
    InvalidBinding,
    #[error("le pair n'a pas présenté de clé statique Noise")]
    MissingRemoteStatic,
    #[error("message de {0} octets trop grand pour une trame Noise")]
    MessageTooLarge(usize),
    #[error("erreur Noise : {0}")]
    Noise(#[from] snow::Error),
}
