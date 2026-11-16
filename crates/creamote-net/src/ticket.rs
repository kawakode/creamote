//! Tickets de session et décision d'accepter une offre côté host.
//!
//! Un host **enrôlé** dans un parc n'accepte une session que sur présentation
//! d'un ticket signé par la clé de tickets de son serveur (épinglée à
//! l'enrôlement), émis pour ce host **et** pour la clé du viewer qui se
//! présente, encore valide, et accordant les permissions nécessaires.
//!
//! Un host non enrôlé reste en mode développement : il accepte toute offre,
//! sans ticket (le consentement et le mot de passe ponctuel arrivent avec M2).

use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use creamote_crypto::identity::verify_ed25519;
use creamote_crypto::{DeviceIdentity, PublicIdentity};
use creamote_proto::permissions::Permissions;
use creamote_proto::ticket::v1::{SessionTicket, SignedTicket};
use prost::Message;

pub const TICKET_VERSION: u32 = 1;
/// Durée de validité d'un ticket : le temps d'ouvrir la session.
pub const TICKET_TTL_SECS: i64 = 120;
/// Tolérance de décalage d'horloge entre serveur et host.
pub const CLOCK_SKEW_SECS: i64 = 60;
const CONTEXT: &[u8] = b"creamote/ticket/v1";

pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn signed_message(ticket: &[u8]) -> Vec<u8> {
    [CONTEXT, ticket].concat()
}

/// Signe un ticket avec la clé de tickets du serveur.
pub fn sign(key: &DeviceIdentity, ticket: &SessionTicket) -> Vec<u8> {
    let bytes = ticket.encode_to_vec();
    let signature = key.sign(&signed_message(&bytes)).to_bytes().to_vec();
    SignedTicket {
        ticket: bytes,
        signature,
    }
    .encode_to_vec()
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum TicketError {
    #[error("ticket absent")]
    Missing,
    #[error("ticket illisible")]
    Malformed,
    #[error("version de ticket non prise en charge")]
    UnsupportedVersion,
    #[error("signature du ticket invalide")]
    BadSignature,
    #[error("ticket émis pour un autre host")]
    WrongHost,
    #[error("ticket émis pour un autre viewer")]
    WrongViewer,
    #[error("ticket expiré ou pas encore valide")]
    Expired,
    #[error("permission insuffisante : {0:?} requise")]
    Insufficient(Permissions),
}

/// Vérifie un ticket signé et retourne son contenu.
pub fn verify(
    signed: &[u8],
    server_key: &[u8; 32],
    host: &PublicIdentity,
    viewer: &PublicIdentity,
    now: i64,
) -> Result<SessionTicket, TicketError> {
    if signed.is_empty() {
        return Err(TicketError::Missing);
    }
    let signed = SignedTicket::decode(signed).map_err(|_| TicketError::Malformed)?;
    if !verify_ed25519(
        server_key,
        &signed_message(&signed.ticket),
        &signed.signature,
    ) {
        return Err(TicketError::BadSignature);
    }
    let t = SessionTicket::decode(signed.ticket.as_slice()).map_err(|_| TicketError::Malformed)?;
    if t.version != TICKET_VERSION {
        return Err(TicketError::UnsupportedVersion);
    }
    if t.host_signing_key != host.signing_key() {
        return Err(TicketError::WrongHost);
    }
    if t.viewer_signing_key != viewer.signing_key() {
        return Err(TicketError::WrongViewer);
    }
    if now > t.expires_at + CLOCK_SKEW_SECS || now + CLOCK_SKEW_SECS < t.issued_at {
        return Err(TicketError::Expired);
    }
    Ok(t)
}

/// Permissions qu'un ticket doit accorder pour une session sans surveillance
/// (aucun utilisateur présent pour consentir).
pub const UNATTENDED_REQUIRED: Permissions = Permissions::VIEW.union(Permissions::UNATTENDED);

/// Décision du host sur une offre entrante.
#[derive(Debug)]
pub enum Decision {
    /// Mode développement (host non enrôlé) : pas de ticket.
    AcceptUnmanaged,
    /// Ticket valide : session avec ces permissions, pour cet utilisateur.
    Accept(SessionTicket),
    Decline(TicketError),
}

pub fn decide(
    enrollment: Option<&Enrollment>,
    ticket: &[u8],
    host: &PublicIdentity,
    requester: &PublicIdentity,
    now: i64,
) -> Decision {
    let Some(e) = enrollment else {
        return Decision::AcceptUnmanaged;
    };
    match verify(ticket, &e.ticket_key, host, requester, now) {
        Ok(t) if Permissions::from_bits_truncate(t.permissions).contains(UNATTENDED_REQUIRED) => {
            Decision::Accept(t)
        }
        // Le consentement de l'utilisateur présent (M2) permettra d'accepter
        // un ticket sans `unattended`.
        Ok(_) => Decision::Decline(TicketError::Insufficient(UNATTENDED_REQUIRED)),
        Err(e) => Decision::Decline(e),
    }
}

/// État d'enrôlement conservé par le host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrollment {
    pub ticket_key: [u8; 32],
    /// Serveur d'enrôlement (`hôte:port`) et son empreinte.
    pub server: String,
    pub server_pin: String,
    pub entity_name: String,
    pub fleet_name: String,
}

impl Enrollment {
    pub fn load(path: &Path) -> std::io::Result<Option<Self>> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let field = |name: &str| {
            text.lines()
                .find_map(|l| l.strip_prefix(name)?.strip_prefix('='))
                .map(str::to_owned)
        };
        let invalid = || {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "fichier d'enrôlement invalide",
            )
        };
        let key = field("ticket_key").ok_or_else(invalid)?;
        let mut ticket_key = [0u8; 32];
        if key.len() != 64 {
            return Err(invalid());
        }
        for (i, b) in ticket_key.iter_mut().enumerate() {
            *b = u8::from_str_radix(&key[2 * i..2 * i + 2], 16).map_err(|_| invalid())?;
        }
        Ok(Some(Self {
            ticket_key,
            server: field("server").ok_or_else(invalid)?,
            server_pin: field("server_pin").ok_or_else(invalid)?,
            entity_name: field("entity").unwrap_or_default(),
            fleet_name: field("fleet").unwrap_or_default(),
        }))
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let key: String = self.ticket_key.iter().map(|b| format!("{b:02x}")).collect();
        let clean = |s: &str| s.replace(['\n', '\r'], " ");
        let mut f = std::fs::File::create(path)?;
        writeln!(f, "ticket_key={key}")?;
        writeln!(f, "server={}", clean(&self.server))?;
        writeln!(f, "server_pin={}", clean(&self.server_pin))?;
        writeln!(f, "entity={}", clean(&self.entity_name))?;
        writeln!(f, "fleet={}", clean(&self.fleet_name))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Setup {
        server: DeviceIdentity,
        host: DeviceIdentity,
        viewer: DeviceIdentity,
    }

    fn setup() -> Setup {
        Setup {
            server: DeviceIdentity::generate(),
            host: DeviceIdentity::generate(),
            viewer: DeviceIdentity::generate(),
        }
    }

    fn ticket(s: &Setup, perms: Permissions, now: i64) -> Vec<u8> {
        sign(
            &s.server,
            &SessionTicket {
                version: TICKET_VERSION,
                host_signing_key: s.host.public().signing_key().to_vec(),
                viewer_signing_key: s.viewer.public().signing_key().to_vec(),
                user_id: "u".into(),
                user_email: "u@example.org".into(),
                permissions: perms.bits(),
                issued_at: now,
                expires_at: now + TICKET_TTL_SECS,
                entity_id: "e".into(),
            },
        )
    }

    fn enrollment(s: &Setup) -> Enrollment {
        Enrollment {
            ticket_key: *s.server.public().signing_key(),
            server: "relay.example.org:21400".into(),
            server_pin: "pin".into(),
            entity_name: "ACME".into(),
            fleet_name: "Siège".into(),
        }
    }

    #[test]
    fn valid_ticket_is_accepted() {
        let s = setup();
        let t = ticket(&s, Permissions::ALL, 1000);
        let d = decide(
            Some(&enrollment(&s)),
            &t,
            s.host.public(),
            s.viewer.public(),
            1010,
        );
        assert!(matches!(d, Decision::Accept(t) if t.user_email == "u@example.org"));
    }

    #[test]
    fn ticket_is_bound_to_host_viewer_key_and_time() {
        let s = setup();
        let key = s.server.public().signing_key();
        let t = ticket(&s, Permissions::ALL, 1000);
        let other = DeviceIdentity::generate();
        let v = |host: &PublicIdentity, viewer: &PublicIdentity, now| {
            verify(&t, key, host, viewer, now)
        };

        assert_eq!(
            v(other.public(), s.viewer.public(), 1000).unwrap_err(),
            TicketError::WrongHost
        );
        assert_eq!(
            v(s.host.public(), other.public(), 1000).unwrap_err(),
            TicketError::WrongViewer
        );
        assert_eq!(
            v(s.host.public(), s.viewer.public(), 1000 + 10_000).unwrap_err(),
            TicketError::Expired
        );
        assert_eq!(
            v(s.host.public(), s.viewer.public(), 0).unwrap_err(),
            TicketError::Expired
        );
        assert_eq!(
            verify(
                &t,
                other.public().signing_key(),
                s.host.public(),
                s.viewer.public(),
                1000
            )
            .unwrap_err(),
            TicketError::BadSignature
        );
    }

    #[test]
    fn tampered_ticket_fails_signature() {
        let s = setup();
        let mut signed =
            SignedTicket::decode(ticket(&s, Permissions::VIEW, 1000).as_slice()).unwrap();
        let mut t = SessionTicket::decode(signed.ticket.as_slice()).unwrap();
        t.permissions = Permissions::ALL.bits();
        signed.ticket = t.encode_to_vec();
        let forged = signed.encode_to_vec();
        assert_eq!(
            verify(
                &forged,
                s.server.public().signing_key(),
                s.host.public(),
                s.viewer.public(),
                1000
            )
            .unwrap_err(),
            TicketError::BadSignature
        );
    }

    #[test]
    fn enrolled_host_requires_ticket_with_unattended() {
        let s = setup();
        let e = enrollment(&s);
        let d = decide(Some(&e), &[], s.host.public(), s.viewer.public(), 1000);
        assert!(matches!(d, Decision::Decline(TicketError::Missing)));
        let tech = Permissions::VIEW | Permissions::CONTROL;
        let d = decide(
            Some(&e),
            &ticket(&s, tech, 1000),
            s.host.public(),
            s.viewer.public(),
            1000,
        );
        assert!(matches!(d, Decision::Decline(TicketError::Insufficient(_))));
        let d = decide(None, &[], s.host.public(), s.viewer.public(), 1000);
        assert!(matches!(d, Decision::AcceptUnmanaged));
    }

    #[test]
    fn enrollment_file_roundtrip() {
        let s = setup();
        let e = enrollment(&s);
        let dir = std::env::temp_dir().join(format!("creamote-enroll-{}", std::process::id()));
        e.save(&dir).unwrap();
        assert_eq!(Enrollment::load(&dir).unwrap(), Some(e));
        std::fs::remove_file(&dir).unwrap();
        assert_eq!(Enrollment::load(&dir).unwrap(), None);
    }
}
