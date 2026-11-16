//! Mots de passe (Argon2id) et jetons d'API opaques et révocables.

use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use rand_core::{OsRng, RngCore};

/// Longueur minimale d'un mot de passe.
pub const MIN_PASSWORD_LEN: usize = 12;
/// Durée de vie d'un jeton de session d'API.
pub const TOKEN_TTL_SECS: i64 = 12 * 3600;
const TOKEN_PREFIX: &str = "crm_";

pub fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("paramètres Argon2 par défaut valides")
        .to_string()
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .map(|h| {
            Argon2::default()
                .verify_password(password.as_bytes(), &h)
                .is_ok()
        })
        .unwrap_or(false)
}

/// Haché d'un mot de passe factice, pour que la connexion d'un e-mail
/// inconnu prenne le même temps qu'un mauvais mot de passe.
pub fn dummy_hash() -> &'static str {
    use std::sync::OnceLock;
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| hash_password("creamote-dummy-password"))
}

/// Nouveau jeton : (valeur à remettre au client, haché à stocker).
pub fn new_token() -> (String, String) {
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    let token = format!("{TOKEN_PREFIX}{}", hex(&raw));
    let hash = token_hash(&token);
    (token, hash)
}

pub fn token_hash(token: &str) -> String {
    blake3::hash(token.as_bytes()).to_hex().to_string()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_roundtrip() {
        let h = hash_password("correct horse battery");
        assert!(verify_password("correct horse battery", &h));
        assert!(!verify_password("correct horse batterie", &h));
        assert!(!verify_password("x", "pas un haché"));
    }

    #[test]
    fn tokens_are_unique_and_hashed() {
        let (a, ha) = new_token();
        let (b, _) = new_token();
        assert_ne!(a, b);
        assert!(a.starts_with("crm_"));
        assert_eq!(token_hash(&a), ha);
        assert_ne!(a, ha);
    }
}
