//! Double authentification : TOTP (RFC 6238, HMAC-SHA1, 6 chiffres, 30 s),
//! compatible avec les applications d'authentification courantes, et codes de
//! secours à usage unique.

use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha1::Sha1;

pub const STEP_SECS: i64 = 30;
pub const DIGITS: u32 = 6;
/// Pas de temps acceptés de part et d'autre de l'heure courante.
const WINDOW: i64 = 1;
pub const RECOVERY_CODES: usize = 10;

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Nouveau secret de 160 bits, encodé en base32 (sans remplissage).
pub fn new_secret() -> String {
    let mut raw = [0u8; 20];
    OsRng.fill_bytes(&mut raw);
    base32_encode(&raw)
}

pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(BASE32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in s.chars().filter(|c| !c.is_whitespace() && *c != '=') {
        let v = BASE32
            .iter()
            .position(|&x| x == c.to_ascii_uppercase() as u8)? as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

/// Code HOTP (RFC 4226) pour un compteur.
pub fn hotp(key: &[u8], counter: u64) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepte toute longueur de clé");
    mac.update(&counter.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let off = (h[19] & 0x0f) as usize;
    let bin = u32::from_be_bytes([h[off] & 0x7f, h[off + 1], h[off + 2], h[off + 3]]);
    bin % 10u32.pow(DIGITS)
}

/// Vérifie `code` à l'instant `now` ; retourne le pas de temps reconnu, qui
/// doit être strictement supérieur à `last_step` (un code ne sert qu'une
/// fois).
pub fn verify(secret_b32: &str, code: &str, now: i64, last_step: i64) -> Option<i64> {
    let code = code.trim().replace(' ', "");
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let code: u32 = code.parse().ok()?;
    let key = base32_decode(secret_b32)?;
    let current = now.div_euclid(STEP_SECS);
    let mut found = None;
    // Parcours complet de la fenêtre : durée indépendante du code reçu.
    for step in current - WINDOW..=current + WINDOW {
        if step > last_step && step >= 0 && constant_eq(hotp(&key, step as u64), code) {
            found = Some(step);
        }
    }
    found
}

fn constant_eq(a: u32, b: u32) -> bool {
    (a ^ b) == 0
}

/// URI `otpauth://` à scanner par l'application d'authentification.
pub fn otpauth_uri(issuer: &str, account: &str, secret_b32: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={secret_b32}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
        percent(issuer),
        percent(account),
        percent(issuer),
    )
}

fn percent(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'@' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// QR code de l'URI, en SVG.
pub fn qr_svg(data: &str) -> Option<String> {
    let code = qrcode::QrCode::new(data.as_bytes()).ok()?;
    Some(
        code.render::<qrcode::render::svg::Color>()
            .min_dimensions(200, 200)
            .quiet_zone(true)
            .build(),
    )
}

/// Codes de secours lisibles : `xxxx-xxxx` (alphabet sans ambiguïté).
pub fn new_recovery_codes() -> Vec<String> {
    const ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
    (0..RECOVERY_CODES)
        .map(|_| {
            let mut raw = [0u8; 8];
            OsRng.fill_bytes(&mut raw);
            let chars: String = raw
                .iter()
                .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
                .collect();
            format!("{}-{}", &chars[..4], &chars[4..])
        })
        .collect()
}

/// Forme canonique d'un code de secours saisi (casse, espaces, tiret).
pub fn normalize_recovery(code: &str) -> String {
    let c: String = code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if c.len() == 8 {
        format!("{}-{}", &c[..4], &c[4..])
    } else {
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vecteurs de la RFC 6238 (SHA1, clé "12345678901234567890"), 6 derniers
    /// chiffres.
    #[test]
    fn rfc6238_vectors() {
        let key = b"12345678901234567890";
        for (t, expected) in [
            (59u64, 287_082),
            (1_111_111_109, 81_804),
            (1_111_111_111, 50_471),
            (1_234_567_890, 5_924),
            (2_000_000_000, 279_037),
        ] {
            assert_eq!(hotp(key, t / 30), expected, "t={t}");
        }
    }

    #[test]
    fn base32_roundtrip() {
        let secret = new_secret();
        assert_eq!(secret.len(), 32);
        assert_eq!(base32_decode(&secret).unwrap().len(), 20);
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32_decode("mzxw 6ytb oi").unwrap(), b"foobar");
        assert!(base32_decode("1!").is_none());
    }

    #[test]
    fn verify_window_and_replay() {
        let secret = base32_encode(b"12345678901234567890");
        let now = 1_111_111_111;
        let code = format!("{:06}", hotp(b"12345678901234567890", (now / 30) as u64));
        let step = verify(&secret, &code, now, 0).unwrap();
        assert_eq!(step, now / 30);
        assert_eq!(verify(&secret, &code, now, step), None, "rejeu refusé");
        assert!(
            verify(&secret, &code, now + 30, 0).is_some(),
            "pas précédent accepté"
        );
        assert!(verify(&secret, &code, now + 90, 0).is_none(), "trop ancien");
        assert!(verify(&secret, "12345", now, 0).is_none());
        assert!(verify(&secret, "abcdef", now, 0).is_none());
    }

    #[test]
    fn recovery_codes_and_uri() {
        let codes = new_recovery_codes();
        assert_eq!(codes.len(), RECOVERY_CODES);
        assert_eq!(
            normalize_recovery(&codes[0].to_uppercase().replace('-', " ")),
            codes[0]
        );
        let uri = otpauth_uri("Creamote", "a b@example.org", "ABC");
        assert!(
            uri.starts_with("otpauth://totp/Creamote:a%20b@example.org?secret=ABC&issuer=Creamote")
        );
        assert!(qr_svg(&uri).unwrap().starts_with("<?xml"));
    }
}
