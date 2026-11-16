//! Clés de sécurité WebAuthn (FIDO2) comme second facteur : clés USB/NFC
//! (YubiKey, SoloKey…), Windows Hello, Touch ID, passkeys Android.
//!
//! Vérification faite ici, sans OpenSSL : décodage CBOR minimal, clés COSE
//! ES256, EdDSA et RS256, signatures vérifiées avec les primitives RustCrypto
//! de `jsonwebtoken`.
//!
//! Contrôles : type et défi de `clientDataJSON`, origine exacte de la console,
//! empreinte de l'identifiant du site (`rpIdHash`), présence de l'utilisateur,
//! signature, compteur de signatures croissant (détection de clé clonée).
//! Les défis sont aléatoires, à usage unique et valables 5 minutes.
//!
//! L'attestation (preuve du modèle de la clé) est demandée à `none` et n'est
//! pas vérifiée : toute clé conforme est acceptée.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use jsonwebtoken::{Algorithm, DecodingKey};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Algorithmes COSE acceptés, par ordre de préférence.
pub const ES256: i64 = -7;
pub const EDDSA: i64 = -8;
pub const RS256: i64 = -257;

const CHALLENGE_TTL: Duration = Duration::from_secs(300);
const MAX_PENDING: usize = 10_000;
const TIMEOUT_MS: u64 = 120_000;
const MAX_CREDENTIAL_ID: usize = 1023;

const FLAG_UP: u8 = 0x01;
const FLAG_AT: u8 = 0x40;

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum WebAuthnError {
    #[error("défi inconnu ou expiré")]
    UnknownChallenge,
    #[error("trop de demandes en cours")]
    Busy,
    #[error("réponse invalide : {0}")]
    Invalid(&'static str),
    #[error("algorithme de clé non pris en charge")]
    UnsupportedAlgorithm,
    #[error("signature invalide")]
    BadSignature,
    #[error("compteur de signatures en recul : clé peut-être clonée")]
    CounterRegression,
}

type Result<T> = std::result::Result<T, WebAuthnError>;

/// Le site auprès duquel les clés sont enregistrées : la console.
#[derive(Debug, Clone)]
pub struct RelyingParty {
    /// Nom de domaine (`admin.example.org`) ; une clé n'est utilisable que
    /// sur ce domaine.
    pub id: String,
    /// Origine exacte de la console (`https://admin.example.org`).
    pub origin: String,
}

impl RelyingParty {
    /// Depuis l'URL publique de la console. Les navigateurs n'autorisent
    /// WebAuthn qu'en HTTPS (ou sur `localhost`) et jamais sur une adresse IP.
    pub fn from_url(url: &str) -> std::result::Result<Self, String> {
        let u = reqwest::Url::parse(url).map_err(|e| format!("URL publique invalide : {e}"))?;
        let host = u
            .host_str()
            .ok_or("URL publique sans hôte")?
            .to_ascii_lowercase();
        if host.starts_with('[') || host.parse::<std::net::IpAddr>().is_ok() {
            return Err(
                "WebAuthn exige un nom de domaine dans l'URL publique, pas une adresse IP".into(),
            );
        }
        if u.scheme() != "https" && !(u.scheme() == "http" && host == "localhost") {
            return Err("WebAuthn exige une URL publique en https://".into());
        }
        Ok(Self {
            origin: u.origin().ascii_serialization(),
            id: host,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Purpose {
    Register,
    Login,
}

struct Pending {
    purpose: Purpose,
    user_id: String,
    challenge: [u8; 32],
    /// Identifiants de clés acceptés (connexion).
    allowed: Vec<String>,
    expires: Instant,
}

/// Défi de connexion retiré (usage unique) de la file d'attente.
pub struct LoginChallenge {
    pub user_id: String,
    challenge: [u8; 32],
    allowed: Vec<String>,
}

impl LoginChallenge {
    /// La clé fait partie de celles proposées pour ce compte.
    pub fn allows(&self, credential_id: &str) -> bool {
        self.allowed.iter().any(|c| c == credential_id)
    }
}

/// Compte pour lequel enregistrer une clé.
pub struct UserInfo<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub display_name: &'a str,
}

/// Réponse de `navigator.credentials.create()`, champs en base64url.
#[derive(Debug, Clone, Deserialize)]
pub struct RegistrationResponse {
    pub id: String,
    pub client_data_json: String,
    pub attestation_object: String,
}

/// Réponse de `navigator.credentials.get()`, champs en base64url.
#[derive(Debug, Clone, Deserialize)]
pub struct AssertionResponse {
    pub id: String,
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
    #[serde(default)]
    pub user_handle: Option<String>,
}

/// Clé validée, à enregistrer.
#[derive(Debug, Clone)]
pub struct NewCredential {
    /// Identifiant de la clé (base64url).
    pub credential_id: String,
    /// Clé publique COSE (base64url).
    pub public_key: String,
    pub alg: i64,
    pub sign_count: u32,
}

/// Clé enregistrée.
pub struct StoredCredential<'a> {
    pub public_key: &'a str,
    pub sign_count: u32,
}

pub struct WebAuthn {
    rp: RelyingParty,
    pending: Mutex<HashMap<String, Pending>>,
}

impl WebAuthn {
    pub fn new(rp: RelyingParty) -> Self {
        Self {
            rp,
            pending: Mutex::default(),
        }
    }

    pub fn rp(&self) -> &RelyingParty {
        &self.rp
    }

    fn insert(
        &self,
        purpose: Purpose,
        user_id: &str,
        allowed: Vec<String>,
    ) -> Result<(String, [u8; 32])> {
        let mut challenge = [0u8; 32];
        OsRng.fill_bytes(&mut challenge);
        let mut raw_id = [0u8; 16];
        OsRng.fill_bytes(&mut raw_id);
        let id = B64.encode(raw_id);
        let now = Instant::now();
        let mut pending = self.pending.lock().expect("verrou sain");
        pending.retain(|_, p| p.expires > now);
        if pending.len() >= MAX_PENDING {
            return Err(WebAuthnError::Busy);
        }
        pending.insert(
            id.clone(),
            Pending {
                purpose,
                user_id: user_id.to_owned(),
                challenge,
                allowed,
                expires: now + CHALLENGE_TTL,
            },
        );
        Ok((id, challenge))
    }

    fn take(&self, id: &str, purpose: Purpose) -> Result<Pending> {
        let p = self
            .pending
            .lock()
            .expect("verrou sain")
            .remove(id)
            .ok_or(WebAuthnError::UnknownChallenge)?;
        if p.purpose != purpose || p.expires <= Instant::now() {
            return Err(WebAuthnError::UnknownChallenge);
        }
        Ok(p)
    }

    /// Options pour `navigator.credentials.create()` (binaire en base64url).
    pub fn start_registration(&self, user: &UserInfo<'_>, exclude: &[String]) -> Result<Value> {
        let (challenge_id, challenge) = self.insert(Purpose::Register, user.id, Vec::new())?;
        let params: Vec<Value> = [ES256, EDDSA, RS256]
            .iter()
            .map(|alg| json!({ "type": "public-key", "alg": alg }))
            .collect();
        Ok(json!({
            "challenge_id": challenge_id,
            "public_key": {
                "rp": { "id": self.rp.id, "name": "Creamote" },
                "user": {
                    "id": B64.encode(user.id.as_bytes()),
                    "name": user.name,
                    "displayName": user.display_name,
                },
                "challenge": B64.encode(challenge),
                "pubKeyCredParams": params,
                "timeout": TIMEOUT_MS,
                "attestation": "none",
                "authenticatorSelection": {
                    "residentKey": "discouraged",
                    "userVerification": "discouraged",
                },
                "excludeCredentials": exclude
                    .iter()
                    .map(|id| json!({ "type": "public-key", "id": id }))
                    .collect::<Vec<_>>(),
            },
        }))
    }

    /// Valide la réponse d'enregistrement d'une nouvelle clé pour `user_id`.
    pub fn finish_registration(
        &self,
        challenge_id: &str,
        user_id: &str,
        resp: &RegistrationResponse,
    ) -> Result<NewCredential> {
        let p = self.take(challenge_id, Purpose::Register)?;
        if p.user_id != user_id {
            return Err(WebAuthnError::UnknownChallenge);
        }
        let client_data = b64(&resp.client_data_json)?;
        self.check_client_data(&client_data, "webauthn.create", &p.challenge)?;

        let att = cbor::decode_all(&b64(&resp.attestation_object)?)?;
        let auth_data = att
            .text_key("authData")
            .and_then(cbor::Value::bytes)
            .ok_or(WebAuthnError::Invalid("authData absent"))?;
        let ad = AuthData::parse(auth_data)?;
        self.check_auth_data(&ad)?;
        let (cred_id, cose) = ad
            .attested
            .ok_or(WebAuthnError::Invalid("clé publique absente"))?;
        if cred_id.is_empty() || cred_id.len() > MAX_CREDENTIAL_ID {
            return Err(WebAuthnError::Invalid("identifiant de clé"));
        }
        let credential_id = B64.encode(cred_id);
        if b64(&resp.id)? != cred_id {
            return Err(WebAuthnError::Invalid("identifiant de clé"));
        }
        let key = CoseKey::parse(cose)?;
        Ok(NewCredential {
            credential_id,
            public_key: B64.encode(cose),
            alg: key.alg,
            sign_count: ad.sign_count,
        })
    }

    /// Options pour `navigator.credentials.get()`, limitées aux clés du compte.
    pub fn start_login(&self, user_id: &str, allowed: &[String]) -> Result<Value> {
        let (challenge_id, challenge) = self.insert(Purpose::Login, user_id, allowed.to_vec())?;
        Ok(json!({
            "challenge_id": challenge_id,
            "public_key": {
                "rpId": self.rp.id,
                "challenge": B64.encode(challenge),
                "timeout": TIMEOUT_MS,
                "userVerification": "discouraged",
                "allowCredentials": allowed
                    .iter()
                    .map(|id| json!({ "type": "public-key", "id": id }))
                    .collect::<Vec<_>>(),
            },
        }))
    }

    /// Retire le défi de connexion (usage unique, même en cas d'échec).
    pub fn take_login(&self, challenge_id: &str) -> Result<LoginChallenge> {
        let p = self.take(challenge_id, Purpose::Login)?;
        Ok(LoginChallenge {
            user_id: p.user_id,
            challenge: p.challenge,
            allowed: p.allowed,
        })
    }

    /// Vérifie une signature de connexion ; retourne le nouveau compteur.
    pub fn verify_assertion(
        &self,
        ch: &LoginChallenge,
        stored: &StoredCredential<'_>,
        resp: &AssertionResponse,
    ) -> Result<u32> {
        if !ch.allows(&resp.id) {
            return Err(WebAuthnError::Invalid("clé non proposée"));
        }
        if let Some(handle) = resp.user_handle.as_deref().filter(|h| !h.is_empty())
            && b64(handle)? != ch.user_id.as_bytes()
        {
            return Err(WebAuthnError::Invalid("compte de la clé"));
        }
        let client_data = b64(&resp.client_data_json)?;
        self.check_client_data(&client_data, "webauthn.get", &ch.challenge)?;
        let auth_data = b64(&resp.authenticator_data)?;
        let ad = AuthData::parse(&auth_data)?;
        self.check_auth_data(&ad)?;

        let key = CoseKey::parse(&b64(stored.public_key)?)?;
        let mut message = auth_data.clone();
        message.extend_from_slice(&Sha256::digest(&client_data));
        key.verify(&message, &b64(&resp.signature)?)?;

        // Compteur : 0 en permanence pour certaines clés (passkeys) ; sinon
        // il doit croître, faute de quoi la clé a pu être dupliquée.
        if (stored.sign_count != 0 || ad.sign_count != 0) && ad.sign_count <= stored.sign_count {
            return Err(WebAuthnError::CounterRegression);
        }
        Ok(ad.sign_count)
    }

    fn check_client_data(&self, raw: &[u8], kind: &str, challenge: &[u8; 32]) -> Result<()> {
        #[derive(Deserialize)]
        struct ClientData {
            #[serde(rename = "type")]
            kind: String,
            challenge: String,
            origin: String,
            #[serde(rename = "crossOrigin", default)]
            cross_origin: bool,
        }
        let cd: ClientData =
            serde_json::from_slice(raw).map_err(|_| WebAuthnError::Invalid("clientDataJSON"))?;
        if cd.kind != kind {
            return Err(WebAuthnError::Invalid("type de cérémonie"));
        }
        if b64(&cd.challenge)? != challenge {
            return Err(WebAuthnError::Invalid("défi"));
        }
        if cd.origin != self.rp.origin || cd.cross_origin {
            return Err(WebAuthnError::Invalid("origine"));
        }
        Ok(())
    }

    fn check_auth_data(&self, ad: &AuthData<'_>) -> Result<()> {
        if ad.rp_id_hash != Sha256::digest(self.rp.id.as_bytes()).as_slice() {
            return Err(WebAuthnError::Invalid("site (rpIdHash)"));
        }
        if ad.flags & FLAG_UP == 0 {
            return Err(WebAuthnError::Invalid("présence de l'utilisateur"));
        }
        Ok(())
    }
}

fn b64(s: &str) -> Result<Vec<u8>> {
    B64.decode(s.trim_end_matches('='))
        .map_err(|_| WebAuthnError::Invalid("base64url"))
}

/// Données de l'authentificateur (WebAuthn §6.1).
struct AuthData<'a> {
    rp_id_hash: &'a [u8],
    flags: u8,
    sign_count: u32,
    /// (identifiant de la clé, clé publique COSE) à l'enregistrement.
    attested: Option<(&'a [u8], &'a [u8])>,
}

impl<'a> AuthData<'a> {
    fn parse(d: &'a [u8]) -> Result<Self> {
        let bad = WebAuthnError::Invalid("authenticatorData");
        if d.len() < 37 {
            return Err(bad);
        }
        let flags = d[32];
        let sign_count = u32::from_be_bytes([d[33], d[34], d[35], d[36]]);
        let attested = if flags & FLAG_AT != 0 {
            // AAGUID (16 octets), longueur de l'identifiant (2), identifiant,
            // puis la clé COSE (suivie d'éventuelles extensions).
            let rest = d.get(37 + 16..).ok_or(bad.clone())?;
            let len = usize::from(u16::from_be_bytes([
                *rest.first().ok_or(bad.clone())?,
                *rest.get(1).ok_or(bad.clone())?,
            ]));
            let cred_id = rest.get(2..2 + len).ok_or(bad.clone())?;
            let after = &rest[2 + len..];
            let (_, used) = cbor::decode(after)?;
            Some((cred_id, &after[..used]))
        } else {
            None
        };
        Ok(Self {
            rp_id_hash: &d[..32],
            flags,
            sign_count,
            attested,
        })
    }
}

/// Clé publique COSE (RFC 9053).
struct CoseKey {
    alg: i64,
    key: DecodingKey,
}

impl CoseKey {
    fn parse(raw: &[u8]) -> Result<Self> {
        let m = cbor::decode_all(raw)?;
        let int = |k: i64| m.int_key(k);
        let bytes = |k: i64| int(k).and_then(cbor::Value::bytes);
        let kty = int(1).and_then(cbor::Value::int);
        let alg = int(3)
            .and_then(cbor::Value::int)
            .ok_or(WebAuthnError::UnsupportedAlgorithm)?;
        let bad = WebAuthnError::Invalid("clé COSE");
        let key = match (kty, alg) {
            // EC2, P-256.
            (Some(2), ES256) => {
                let (x, y) = (bytes(-2).ok_or(bad.clone())?, bytes(-3).ok_or(bad.clone())?);
                if int(-1).and_then(cbor::Value::int) != Some(1) || x.len() != 32 || y.len() != 32 {
                    return Err(bad);
                }
                DecodingKey::from_ec_components(&B64.encode(x), &B64.encode(y))
                    .map_err(|_| bad.clone())?
            }
            // OKP, Ed25519.
            (Some(1), EDDSA) => {
                let x = bytes(-2).ok_or(bad.clone())?;
                if int(-1).and_then(cbor::Value::int) != Some(6) || x.len() != 32 {
                    return Err(bad);
                }
                DecodingKey::from_ed_components(&B64.encode(x)).map_err(|_| bad.clone())?
            }
            // RSA, 2048 bits au moins.
            (Some(3), RS256) => {
                let (n, e) = (bytes(-1).ok_or(bad.clone())?, bytes(-2).ok_or(bad.clone())?);
                let n_bits = n.iter().skip_while(|b| **b == 0).count() * 8;
                if n_bits < 2048 || e.is_empty() || e.len() > 8 {
                    return Err(bad);
                }
                DecodingKey::from_rsa_raw_components(n, e)
            }
            _ => return Err(WebAuthnError::UnsupportedAlgorithm),
        };
        Ok(Self { alg, key })
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        let (alg, sig) = match self.alg {
            // WebAuthn transmet les signatures ECDSA en DER ; la vérification
            // attend r || s.
            ES256 => (Algorithm::ES256, der_to_raw_p256(signature)?),
            EDDSA => (Algorithm::EdDSA, signature.to_vec()),
            RS256 => (Algorithm::RS256, signature.to_vec()),
            _ => return Err(WebAuthnError::UnsupportedAlgorithm),
        };
        match jsonwebtoken::crypto::verify(&B64.encode(sig), message, &self.key, alg) {
            Ok(true) => Ok(()),
            _ => Err(WebAuthnError::BadSignature),
        }
    }
}

/// Signature ECDSA P-256 : `SEQUENCE { INTEGER r, INTEGER s }` → `r || s`.
pub fn der_to_raw_p256(der: &[u8]) -> Result<Vec<u8>> {
    let bad = WebAuthnError::BadSignature;
    let (&tag, rest) = der.split_first().ok_or(bad.clone())?;
    let (&len, body) = rest.split_first().ok_or(bad.clone())?;
    if tag != 0x30 || usize::from(len) != body.len() {
        return Err(bad);
    }
    let mut out = Vec::with_capacity(64);
    let mut body = body;
    for _ in 0..2 {
        let (&t, rest) = body.split_first().ok_or(bad.clone())?;
        let (&l, rest) = rest.split_first().ok_or(bad.clone())?;
        let l = usize::from(l);
        if t != 0x02 || l == 0 || l > 33 || rest.len() < l {
            return Err(bad);
        }
        let int = &rest[..l];
        let int = int.strip_prefix(&[0]).unwrap_or(int);
        if int.len() > 32 {
            return Err(bad);
        }
        out.extend(std::iter::repeat_n(0, 32 - int.len()));
        out.extend_from_slice(int);
        body = &rest[l..];
    }
    if !body.is_empty() {
        return Err(bad);
    }
    Ok(out)
}

/// Décodeur CBOR (RFC 8949) restreint à ce qu'emploient les authentificateurs :
/// longueurs définies uniquement, profondeur bornée.
pub mod cbor {
    use super::{Result, WebAuthnError};

    const MAX_DEPTH: usize = 16;

    #[derive(Debug, Clone, PartialEq)]
    pub enum Value {
        Uint(u64),
        /// Entier négatif `-1 - n`.
        Nint(u64),
        Bytes(Vec<u8>),
        Text(String),
        Array(Vec<Value>),
        Map(Vec<(Value, Value)>),
        Bool(bool),
        Null,
        /// Flottant ou valeur simple, non interprétés.
        Other,
    }

    impl Value {
        pub fn int(&self) -> Option<i64> {
            match self {
                Value::Uint(n) => i64::try_from(*n).ok(),
                Value::Nint(n) => i64::try_from(*n).ok().map(|n| -1 - n),
                _ => None,
            }
        }

        pub fn bytes(&self) -> Option<&[u8]> {
            match self {
                Value::Bytes(b) => Some(b),
                _ => None,
            }
        }

        fn entries(&self) -> &[(Value, Value)] {
            match self {
                Value::Map(m) => m,
                _ => &[],
            }
        }

        pub fn int_key(&self, k: i64) -> Option<&Value> {
            self.entries()
                .iter()
                .find(|(key, _)| key.int() == Some(k))
                .map(|(_, v)| v)
        }

        pub fn text_key(&self, k: &str) -> Option<&Value> {
            self.entries()
                .iter()
                .find(|(key, _)| matches!(key, Value::Text(t) if t == k))
                .map(|(_, v)| v)
        }
    }

    /// Décode une valeur en tête de `input` ; retourne aussi la longueur lue.
    pub fn decode(input: &[u8]) -> Result<(Value, usize)> {
        let mut pos = 0;
        let v = item(input, &mut pos, 0)?;
        Ok((v, pos))
    }

    /// Décode une valeur qui occupe exactement `input`.
    pub fn decode_all(input: &[u8]) -> Result<Value> {
        let (v, used) = decode(input)?;
        if used != input.len() {
            return Err(WebAuthnError::Invalid("CBOR : données en trop"));
        }
        Ok(v)
    }

    fn take<'a>(input: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8]> {
        let end = pos
            .checked_add(n)
            .filter(|e| *e <= input.len())
            .ok_or(WebAuthnError::Invalid("CBOR tronqué"))?;
        let s = &input[*pos..end];
        *pos = end;
        Ok(s)
    }

    fn item(input: &[u8], pos: &mut usize, depth: usize) -> Result<Value> {
        if depth > MAX_DEPTH {
            return Err(WebAuthnError::Invalid("CBOR trop imbriqué"));
        }
        let ib = take(input, pos, 1)?[0];
        let (major, ai) = (ib >> 5, ib & 0x1f);
        let arg = match ai {
            0..=23 => u64::from(ai),
            24 => u64::from(take(input, pos, 1)?[0]),
            25 => u64::from(u16::from_be_bytes(take(input, pos, 2)?.try_into().unwrap())),
            26 => u64::from(u32::from_be_bytes(take(input, pos, 4)?.try_into().unwrap())),
            27 => u64::from_be_bytes(take(input, pos, 8)?.try_into().unwrap()),
            _ => return Err(WebAuthnError::Invalid("CBOR : longueur indéfinie")),
        };
        let remaining = (input.len() - *pos) as u64;
        Ok(match major {
            0 => Value::Uint(arg),
            1 => Value::Nint(arg),
            2 | 3 => {
                if arg > remaining {
                    return Err(WebAuthnError::Invalid("CBOR tronqué"));
                }
                let b = take(input, pos, arg as usize)?.to_vec();
                if major == 2 {
                    Value::Bytes(b)
                } else {
                    Value::Text(
                        String::from_utf8(b).map_err(|_| WebAuthnError::Invalid("CBOR : UTF-8"))?,
                    )
                }
            }
            4 => {
                if arg > remaining {
                    return Err(WebAuthnError::Invalid("CBOR tronqué"));
                }
                let mut v = Vec::with_capacity(arg as usize);
                for _ in 0..arg {
                    v.push(item(input, pos, depth + 1)?);
                }
                Value::Array(v)
            }
            5 => {
                if arg.saturating_mul(2) > remaining {
                    return Err(WebAuthnError::Invalid("CBOR tronqué"));
                }
                let mut m = Vec::with_capacity(arg as usize);
                for _ in 0..arg {
                    let k = item(input, pos, depth + 1)?;
                    let v = item(input, pos, depth + 1)?;
                    m.push((k, v));
                }
                Value::Map(m)
            }
            // Étiquette : on garde la valeur étiquetée.
            6 => item(input, pos, depth + 1)?,
            _ => match ai {
                20 => Value::Bool(false),
                21 => Value::Bool(true),
                22 => Value::Null,
                _ => Value::Other,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relying_party_from_public_url() {
        let rp = RelyingParty::from_url("https://Admin.Example.org:8443/console/").unwrap();
        assert_eq!(rp.id, "admin.example.org");
        assert_eq!(rp.origin, "https://admin.example.org:8443");
        let rp = RelyingParty::from_url("https://admin.example.org").unwrap();
        assert_eq!(rp.origin, "https://admin.example.org");
        assert!(RelyingParty::from_url("http://localhost:21401").is_ok());
        assert!(RelyingParty::from_url("http://admin.example.org").is_err());
        assert!(RelyingParty::from_url("https://192.0.2.1").is_err());
        assert!(RelyingParty::from_url("pas une url").is_err());
    }

    #[test]
    fn cbor_decoding() {
        // {1: 2, 3: -7, -1: h'0102', "a": [true, null]}
        let data = [
            0xa4, 0x01, 0x02, 0x03, 0x26, 0x20, 0x42, 0x01, 0x02, 0x61, b'a', 0x82, 0xf5, 0xf6,
        ];
        let v = cbor::decode_all(&data).unwrap();
        assert_eq!(v.int_key(1).and_then(cbor::Value::int), Some(2));
        assert_eq!(v.int_key(3).and_then(cbor::Value::int), Some(-7));
        assert_eq!(
            v.int_key(-1).and_then(cbor::Value::bytes),
            Some(&[1u8, 2][..])
        );
        assert_eq!(
            v.text_key("a"),
            Some(&cbor::Value::Array(vec![
                cbor::Value::Bool(true),
                cbor::Value::Null
            ]))
        );
        // Tronqué, longueur indéfinie, longueur annoncée énorme, données en trop.
        assert!(cbor::decode_all(&data[..5]).is_err());
        assert!(cbor::decode_all(&[0x5f]).is_err());
        assert!(cbor::decode_all(&[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).is_err());
        assert!(cbor::decode_all(&[0x01, 0x02]).is_err());
        // Imbrication excessive.
        assert!(cbor::decode_all(&[0x81; 40]).is_err());
    }

    #[test]
    fn der_signature_conversion() {
        // r avec octet de signe, s court.
        let mut der = vec![0x30, 0x27, 0x02, 0x21, 0x00];
        der.extend([0x80; 32]);
        der.extend([0x02, 0x02, 0x01, 0x02]);
        let raw = der_to_raw_p256(&der).unwrap();
        assert_eq!(&raw[..32], &[0x80; 32]);
        assert_eq!(&raw[32..62], &[0; 30]);
        assert_eq!(&raw[62..], &[1, 2]);
        assert!(der_to_raw_p256(&der[..10]).is_err());
        assert!(der_to_raw_p256(&[0x30, 0x00]).is_err());
    }

    #[test]
    fn challenges_are_single_use_and_bound() {
        let w = WebAuthn::new(RelyingParty::from_url("https://admin.example.org").unwrap());
        let opts = w.start_login("u1", &["a".into()]).unwrap();
        let id = opts["challenge_id"].as_str().unwrap().to_owned();
        assert_eq!(opts["public_key"]["rpId"], "admin.example.org");
        let ch = w.take_login(&id).unwrap();
        assert_eq!(ch.user_id, "u1");
        assert!(ch.allows("a") && !ch.allows("b"));
        assert_eq!(
            w.take_login(&id).err(),
            Some(WebAuthnError::UnknownChallenge)
        );

        // Un défi d'enregistrement ne sert pas à la connexion.
        let user = UserInfo {
            id: "u1",
            name: "a@example.org",
            display_name: "A",
        };
        let reg = w.start_registration(&user, &[]).unwrap();
        let id = reg["challenge_id"].as_str().unwrap();
        assert!(w.take_login(id).is_err());
    }
}
