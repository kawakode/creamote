//! Handshake Noise XX authentifié par les identités Creamote.
//!
//! ```text
//! initiateur (viewer)                     répondeur (host)
//!   -> e                                   (msg1)
//!   <- e, ee, s, es   + identité host      (msg2)
//!   -> s, se          + identité viewer    (msg3)
//! ```
//!
//! Chaque côté joint à sa clé statique Noise sa clé Ed25519 et la signature qui
//! les lie. Le pair vérifie cette signature **contre la clé statique que Noise a
//! effectivement authentifiée** : on obtient ainsi l'identité Creamote du pair,
//! sans faire confiance au serveur ni au relay qui transportent les messages.
//!
//! L'API est typée par étape, pour qu'on ne puisse pas chiffrer avant la fin du
//! handshake ni sauter une vérification.

use snow::{Builder, HandshakeState, TransportState};

use crate::CryptoError;
use crate::identity::{DeviceIdentity, PublicIdentity};

/// Suite Noise utilisée par Creamote.
pub const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Taille maximale d'un message Noise (spécification Noise).
pub const MAX_NOISE_MSG_LEN: usize = 65_535;
const TAG_LEN: usize = 16;
/// Taille maximale d'un clair chiffrable en une fois.
pub const MAX_PLAINTEXT_LEN: usize = MAX_NOISE_MSG_LEN - TAG_LEN;

const IDENTITY_PAYLOAD_LEN: usize = 32 + 64;

fn builder() -> Builder<'static> {
    Builder::new(NOISE_PARAMS.parse().expect("paramètres Noise valides"))
}

fn identity_payload(id: &DeviceIdentity) -> [u8; IDENTITY_PAYLOAD_LEN] {
    let mut out = [0u8; IDENTITY_PAYLOAD_LEN];
    out[..32].copy_from_slice(id.public().signing_key());
    out[32..].copy_from_slice(&id.public().binding());
    out
}

/// Vérifie l'identité jointe par le pair contre la clé statique authentifiée
/// par Noise.
fn remote_identity(hs: &HandshakeState, payload: &[u8]) -> Result<PublicIdentity, CryptoError> {
    if payload.len() != IDENTITY_PAYLOAD_LEN {
        return Err(CryptoError::InvalidIdentity);
    }
    let remote_static = hs
        .get_remote_static()
        .ok_or(CryptoError::MissingRemoteStatic)?;
    PublicIdentity::from_parts(&payload[..32], remote_static, &payload[32..])
}

/// Côté qui ouvre la session (le viewer).
pub struct Initiator<'a> {
    hs: HandshakeState,
    local: &'a DeviceIdentity,
}

impl<'a> Initiator<'a> {
    /// Démarre le handshake ; retourne le premier message à envoyer.
    pub fn start(local: &'a DeviceIdentity) -> Result<(Self, Vec<u8>), CryptoError> {
        let mut hs = builder()
            .local_private_key(local.noise_private())?
            .build_initiator()?;
        let mut buf = vec![0u8; MAX_NOISE_MSG_LEN];
        let n = hs.write_message(&[], &mut buf)?;
        buf.truncate(n);
        Ok((Self { hs, local }, buf))
    }

    /// Traite la réponse du répondeur. Retourne la session prête, le dernier
    /// message à envoyer, et l'identité vérifiée du répondeur.
    pub fn finish(
        mut self,
        msg2: &[u8],
    ) -> Result<(SecureSession, Vec<u8>, PublicIdentity), CryptoError> {
        let mut payload = vec![0u8; MAX_NOISE_MSG_LEN];
        let n = self.hs.read_message(msg2, &mut payload)?;
        let remote = remote_identity(&self.hs, &payload[..n])?;

        let mut msg3 = vec![0u8; MAX_NOISE_MSG_LEN];
        let n = self
            .hs
            .write_message(&identity_payload(self.local), &mut msg3)?;
        msg3.truncate(n);
        Ok((SecureSession::new(self.hs)?, msg3, remote))
    }
}

/// Côté qui accepte la session (le host).
pub struct Responder<'a> {
    hs: HandshakeState,
    local: &'a DeviceIdentity,
}

impl<'a> Responder<'a> {
    pub fn new(local: &'a DeviceIdentity) -> Result<Self, CryptoError> {
        let hs = builder()
            .local_private_key(local.noise_private())?
            .build_responder()?;
        Ok(Self { hs, local })
    }

    /// Traite le premier message ; retourne la réponse à envoyer.
    pub fn respond(
        mut self,
        msg1: &[u8],
    ) -> Result<(ResponderAwaitingFinish, Vec<u8>), CryptoError> {
        let mut scratch = vec![0u8; MAX_NOISE_MSG_LEN];
        self.hs.read_message(msg1, &mut scratch)?;

        let mut msg2 = vec![0u8; MAX_NOISE_MSG_LEN];
        let n = self
            .hs
            .write_message(&identity_payload(self.local), &mut msg2)?;
        msg2.truncate(n);
        Ok((ResponderAwaitingFinish { hs: self.hs }, msg2))
    }
}

/// Répondeur en attente du dernier message de l'initiateur.
pub struct ResponderAwaitingFinish {
    hs: HandshakeState,
}

impl ResponderAwaitingFinish {
    /// Traite le dernier message ; retourne la session et l'identité vérifiée
    /// de l'initiateur.
    pub fn finish(mut self, msg3: &[u8]) -> Result<(SecureSession, PublicIdentity), CryptoError> {
        let mut payload = vec![0u8; MAX_NOISE_MSG_LEN];
        let n = self.hs.read_message(msg3, &mut payload)?;
        let remote = remote_identity(&self.hs, &payload[..n])?;
        Ok((SecureSession::new(self.hs)?, remote))
    }
}

/// Canal chiffré de bout en bout, une fois le handshake terminé.
///
/// Prévu pour un flux fiable et ordonné. Les datagrammes vidéo non fiables
/// utiliseront un mode à nonce explicite dans un prochain milestone.
pub struct SecureSession {
    transport: TransportState,
    handshake_hash: [u8; 32],
}

impl SecureSession {
    fn new(hs: HandshakeState) -> Result<Self, CryptoError> {
        let mut handshake_hash = [0u8; 32];
        handshake_hash.copy_from_slice(&hs.get_handshake_hash()[..32]);
        Ok(Self {
            transport: hs.into_transport_mode()?,
            handshake_hash,
        })
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if plaintext.len() > MAX_PLAINTEXT_LEN {
            return Err(CryptoError::MessageTooLarge(plaintext.len()));
        }
        let mut out = vec![0u8; plaintext.len() + TAG_LEN];
        let n = self.transport.write_message(plaintext, &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() > MAX_NOISE_MSG_LEN {
            return Err(CryptoError::MessageTooLarge(ciphertext.len()));
        }
        let mut out = vec![0u8; ciphertext.len()];
        let n = self.transport.read_message(ciphertext, &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    /// Haché du handshake, identique des deux côtés. Sert à dériver un code de
    /// vérification court affichable aux deux utilisateurs.
    pub fn handshake_hash(&self) -> &[u8; 32] {
        &self.handshake_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handshake(
        viewer: &DeviceIdentity,
        host: &DeviceIdentity,
    ) -> (SecureSession, PublicIdentity, SecureSession, PublicIdentity) {
        let (init, msg1) = Initiator::start(viewer).unwrap();
        let (resp, msg2) = Responder::new(host).unwrap().respond(&msg1).unwrap();
        let (viewer_sess, msg3, seen_host) = init.finish(&msg2).unwrap();
        let (host_sess, seen_viewer) = resp.finish(&msg3).unwrap();
        (viewer_sess, seen_host, host_sess, seen_viewer)
    }

    #[test]
    fn both_sides_learn_verified_identities() {
        let viewer = DeviceIdentity::generate();
        let host = DeviceIdentity::generate();
        let (v, seen_host, h, seen_viewer) = handshake(&viewer, &host);
        assert_eq!(&seen_host, host.public());
        assert_eq!(&seen_viewer, viewer.public());
        assert_eq!(v.handshake_hash(), h.handshake_hash());
    }

    #[test]
    fn transport_roundtrip_both_directions() {
        let viewer = DeviceIdentity::generate();
        let host = DeviceIdentity::generate();
        let (mut v, _, mut h, _) = handshake(&viewer, &host);

        let c = v.encrypt(b"clic gauche").unwrap();
        assert_ne!(&c[..], b"clic gauche");
        assert_eq!(h.decrypt(&c).unwrap(), b"clic gauche");

        let c = h.encrypt(b"image").unwrap();
        assert_eq!(v.decrypt(&c).unwrap(), b"image");
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let viewer = DeviceIdentity::generate();
        let host = DeviceIdentity::generate();
        let (mut v, _, mut h, _) = handshake(&viewer, &host);
        let mut c = v.encrypt(b"secret").unwrap();
        c[0] ^= 1;
        assert!(h.decrypt(&c).is_err());
    }

    #[test]
    fn impersonation_with_foreign_binding_fails() {
        // Un attaquant possède sa propre clé Noise mais rejoue l'identité
        // Ed25519 (et la signature de liaison) d'un host légitime.
        let legit_host = DeviceIdentity::generate();
        let attacker = DeviceIdentity::generate();
        let viewer = DeviceIdentity::generate();

        let (init, msg1) = Initiator::start(&viewer).unwrap();
        let mut hs = builder()
            .local_private_key(attacker.noise_private())
            .unwrap()
            .build_responder()
            .unwrap();
        let mut scratch = vec![0u8; MAX_NOISE_MSG_LEN];
        hs.read_message(&msg1, &mut scratch).unwrap();
        let mut msg2 = vec![0u8; MAX_NOISE_MSG_LEN];
        let n = hs
            .write_message(&identity_payload(&legit_host), &mut msg2)
            .unwrap();
        msg2.truncate(n);

        assert!(matches!(
            init.finish(&msg2),
            Err(CryptoError::InvalidBinding)
        ));
    }

    #[test]
    fn oversized_plaintext_is_rejected() {
        let viewer = DeviceIdentity::generate();
        let host = DeviceIdentity::generate();
        let (mut v, _, _, _) = handshake(&viewer, &host);
        let big = vec![0u8; MAX_PLAINTEXT_LEN + 1];
        assert!(matches!(
            v.encrypt(&big),
            Err(CryptoError::MessageTooLarge(_))
        ));
    }
}
