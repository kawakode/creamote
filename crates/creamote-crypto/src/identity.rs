//! Identité d'un appareil.
//!
//! Une identité se compose :
//! - d'une clé de signature Ed25519, source de vérité de l'identité ;
//! - d'une clé statique X25519 utilisée par Noise ;
//! - d'une signature Ed25519 de la clé Noise (la « liaison »), qui permet à un
//!   pair de vérifier que la clé Noise présentée appartient bien à l'identité.

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use zeroize::Zeroizing;

use crate::CryptoError;

const BINDING_CONTEXT: &[u8] = b"creamote/noise-static-binding/v1";

/// Taille de la forme sérialisée de [`DeviceIdentity::to_secret_bytes`].
pub const SECRET_LEN: usize = 64;

/// Taille de la forme sérialisée de [`PublicIdentity::to_bytes`].
pub const PUBLIC_LEN: usize = 32 + 32 + 64;

/// Identité privée d'un appareil. À stocker dans le coffre de l'OS.
pub struct DeviceIdentity {
    signing: SigningKey,
    noise_secret: StaticSecret,
    public: PublicIdentity,
}

impl DeviceIdentity {
    /// Génère une nouvelle identité aléatoire.
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        let noise_secret = StaticSecret::random_from_rng(OsRng);
        Self::from_parts(signing, noise_secret)
    }

    fn from_parts(signing: SigningKey, noise_secret: StaticSecret) -> Self {
        let noise_static = X25519Public::from(&noise_secret).to_bytes();
        let signature = signing.sign(&binding_message(&noise_static));
        let public = PublicIdentity {
            signing_key: signing.verifying_key(),
            noise_static,
            binding: signature,
        };
        Self {
            signing,
            noise_secret,
            public,
        }
    }

    /// Restaure une identité depuis [`Self::to_secret_bytes`].
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let bytes: &[u8; SECRET_LEN] =
            bytes.try_into().map_err(|_| CryptoError::InvalidIdentity)?;
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&bytes[..32]);
        let mut noise = Zeroizing::new([0u8; 32]);
        noise.copy_from_slice(&bytes[32..]);
        Ok(Self::from_parts(
            SigningKey::from_bytes(&seed),
            StaticSecret::from(*noise),
        ))
    }

    /// Sérialise les secrets (graine Ed25519 puis secret X25519).
    pub fn to_secret_bytes(&self) -> Zeroizing<[u8; SECRET_LEN]> {
        let mut out = Zeroizing::new([0u8; SECRET_LEN]);
        out[..32].copy_from_slice(&self.signing.to_bytes());
        out[32..].copy_from_slice(self.noise_secret.as_bytes());
        out
    }

    pub fn public(&self) -> &PublicIdentity {
        &self.public
    }

    pub fn device_id(&self) -> DeviceId {
        self.public.device_id()
    }

    /// Signe un message arbitraire avec la clé d'identité.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing.sign(msg)
    }

    pub(crate) fn noise_private(&self) -> &[u8; 32] {
        self.noise_secret.as_bytes()
    }
}

impl fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceIdentity")
            .field("device_id", &self.device_id())
            .finish_non_exhaustive()
    }
}

/// Partie publique et vérifiable d'une identité.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicIdentity {
    signing_key: VerifyingKey,
    noise_static: [u8; 32],
    binding: Signature,
}

impl PublicIdentity {
    /// Construit et **vérifie** une identité publique reçue d'un pair.
    pub fn from_parts(
        signing_key: &[u8],
        noise_static: &[u8],
        binding: &[u8],
    ) -> Result<Self, CryptoError> {
        let signing_key: &[u8; 32] = signing_key
            .try_into()
            .map_err(|_| CryptoError::InvalidIdentity)?;
        let signing_key =
            VerifyingKey::from_bytes(signing_key).map_err(|_| CryptoError::InvalidIdentity)?;
        let noise_static: [u8; 32] = noise_static
            .try_into()
            .map_err(|_| CryptoError::InvalidIdentity)?;
        let binding = Signature::from_slice(binding).map_err(|_| CryptoError::InvalidIdentity)?;
        signing_key
            .verify_strict(&binding_message(&noise_static), &binding)
            .map_err(|_| CryptoError::InvalidBinding)?;
        Ok(Self {
            signing_key,
            noise_static,
            binding,
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != PUBLIC_LEN {
            return Err(CryptoError::InvalidIdentity);
        }
        Self::from_parts(&bytes[..32], &bytes[32..64], &bytes[64..])
    }

    pub fn to_bytes(&self) -> [u8; PUBLIC_LEN] {
        let mut out = [0u8; PUBLIC_LEN];
        out[..32].copy_from_slice(self.signing_key.as_bytes());
        out[32..64].copy_from_slice(&self.noise_static);
        out[64..].copy_from_slice(&self.binding.to_bytes());
        out
    }

    pub fn signing_key(&self) -> &[u8; 32] {
        self.signing_key.as_bytes()
    }

    pub fn noise_static(&self) -> &[u8; 32] {
        &self.noise_static
    }

    pub fn binding(&self) -> [u8; 64] {
        self.binding.to_bytes()
    }

    /// Vérifie une signature produite par [`DeviceIdentity::sign`].
    pub fn verify(&self, msg: &[u8], signature: &[u8]) -> bool {
        Signature::from_slice(signature)
            .and_then(|sig| self.signing_key.verify(msg, &sig))
            .is_ok()
    }

    pub fn device_id(&self) -> DeviceId {
        DeviceId::from_signing_key(self.signing_key.as_bytes())
    }

    /// Empreinte lisible de la clé d'identité, pour vérification hors bande
    /// (ex. `3F2A-9C1E-5B7D-4E8A-9C21-7D4E-5F6A-8B90`).
    pub fn fingerprint(&self) -> String {
        let hash = blake3::hash(self.signing_key.as_bytes());
        hash.as_bytes()[..16]
            .chunks(2)
            .map(|c| format!("{:02X}{:02X}", c[0], c[1]))
            .collect::<Vec<_>>()
            .join("-")
    }
}

impl fmt::Debug for PublicIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicIdentity")
            .field("device_id", &self.device_id())
            .field("fingerprint", &self.fingerprint())
            .finish()
    }
}

/// ID à 9 chiffres affiché à l'utilisateur, dérivé de la clé d'identité.
///
/// C'est un raccourci de saisie, pas une preuve d'identité : deux clés peuvent
/// partager un ID. Le serveur refuse un enregistrement en conflit et la clé
/// publique complète reste la référence.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DeviceId(u32);

impl DeviceId {
    const MODULUS: u64 = 1_000_000_000;

    pub fn from_signing_key(key: &[u8; 32]) -> Self {
        let hash = blake3::Hasher::new_derive_key("creamote/device-id/v1")
            .update(key)
            .finalize();
        let mut first = [0u8; 8];
        first.copy_from_slice(&hash.as_bytes()[..8]);
        Self((u64::from_le_bytes(first) % Self::MODULUS) as u32)
    }

    /// Accepte « 123 456 789 », « 123-456-789 » ou « 123456789 ».
    pub fn parse(s: &str) -> Option<Self> {
        let digits: String = s.chars().filter(|c| !matches!(c, ' ' | '-')).collect();
        if digits.len() != 9 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        digits.parse().ok().map(Self)
    }

    pub fn as_u32(self) -> u32 {
        self.0
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = self.0;
        write!(
            f,
            "{:03} {:03} {:03}",
            n / 1_000_000,
            (n / 1_000) % 1_000,
            n % 1_000
        )
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceId({self})")
    }
}

/// Vérifie une signature Ed25519 brute (ex. tickets signés par la clé de
/// tickets d'un serveur).
pub fn verify_ed25519(public_key: &[u8], msg: &[u8], signature: &[u8]) -> bool {
    let Ok(key) = <&[u8; 32]>::try_from(public_key) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(key) else {
        return false;
    };
    Signature::from_slice(signature)
        .and_then(|sig| key.verify_strict(msg, &sig))
        .is_ok()
}

fn binding_message(noise_static: &[u8; 32]) -> Vec<u8> {
    [BINDING_CONTEXT, noise_static.as_slice()].concat()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_roundtrip_preserves_identity() {
        let id = DeviceIdentity::generate();
        let restored = DeviceIdentity::from_secret_bytes(&*id.to_secret_bytes()).unwrap();
        assert_eq!(id.public(), restored.public());
        assert_eq!(id.device_id(), restored.device_id());
    }

    #[test]
    fn public_roundtrip_and_verification() {
        let id = DeviceIdentity::generate();
        let bytes = id.public().to_bytes();
        let parsed = PublicIdentity::from_bytes(&bytes).unwrap();
        assert_eq!(&parsed, id.public());
    }

    #[test]
    fn forged_binding_is_rejected() {
        let a = DeviceIdentity::generate();
        let b = DeviceIdentity::generate();
        // Clé d'identité de A, clé Noise de B : la liaison ne doit pas passer.
        let err = PublicIdentity::from_parts(
            a.public().signing_key(),
            b.public().noise_static(),
            &a.public().binding(),
        )
        .unwrap_err();
        assert!(matches!(err, CryptoError::InvalidBinding));
    }

    #[test]
    fn signatures_verify() {
        let id = DeviceIdentity::generate();
        let sig = id.sign(b"hello");
        assert!(id.public().verify(b"hello", &sig.to_bytes()));
        assert!(!id.public().verify(b"hellO", &sig.to_bytes()));
    }

    #[test]
    fn device_id_format_and_parse() {
        let id = DeviceId(12_345_678);
        assert_eq!(id.to_string(), "012 345 678");
        assert_eq!(DeviceId::parse("012 345 678"), Some(id));
        assert_eq!(DeviceId::parse("012-345-678"), Some(id));
        assert_eq!(DeviceId::parse("012345678"), Some(id));
        assert_eq!(DeviceId::parse("12345678"), None);
        assert_eq!(DeviceId::parse("01234567a"), None);
    }

    #[test]
    fn fingerprint_shape() {
        let fp = DeviceIdentity::generate().public().fingerprint();
        assert_eq!(fp.len(), 8 * 4 + 7);
    }
}
