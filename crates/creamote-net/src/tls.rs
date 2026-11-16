//! QUIC/TLS avec certificat de serveur épinglé.
//!
//! Le serveur génère un certificat auto-signé à son premier démarrage et le
//! conserve. Son **empreinte** (BLAKE3 du certificat DER, 64 caractères hex)
//! est communiquée aux clients avec l'adresse du serveur : c'est elle, et non
//! une autorité de certification, qui authentifie le serveur.

use std::fmt;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

use crate::{NetError, Result, SERVER_NAME};

/// ALPN du protocole Creamote (pair ↔ serveur).
pub const ALPN: &[u8] = b"creamote/1";

/// ALPN des connexions directes entre pairs.
pub const P2P_ALPN: &[u8] = b"creamote-p2p/1";

const CERT_FILE: &str = "server-cert.der";
const KEY_FILE: &str = "server-key.der";

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn transport() -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    t.keep_alive_interval(Some(Duration::from_secs(15)));
    t.max_idle_timeout(Some(
        Duration::from_secs(60)
            .try_into()
            .expect("durée valide pour QUIC"),
    ));
    Arc::new(t)
}

/// Empreinte d'un certificat de serveur.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ServerPin([u8; 32]);

impl ServerPin {
    pub fn of(cert_der: &[u8]) -> Self {
        Self(*blake3::hash(cert_der).as_bytes())
    }
}

impl fmt::Display for ServerPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for ServerPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ServerPin({self})")
    }
}

#[derive(Debug, thiserror::Error)]
#[error("empreinte de serveur invalide (64 caractères hexadécimaux attendus)")]
pub struct InvalidPin;

impl FromStr for ServerPin {
    type Err = InvalidPin;

    fn from_str(s: &str) -> Result<Self, InvalidPin> {
        let s = s.trim();
        if s.len() != 64 || !s.is_ascii() {
            return Err(InvalidPin);
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| InvalidPin)?;
        }
        Ok(Self(out))
    }
}

/// Certificat et clé du serveur.
pub struct ServerCert {
    cert: CertificateDer<'static>,
    key: PrivatePkcs8KeyDer<'static>,
}

impl ServerCert {
    /// Génère un certificat auto-signé éphémère.
    pub fn generate() -> Result<Self> {
        let ck = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_owned()])
            .map_err(|_| NetError::Protocol("génération du certificat impossible"))?;
        Ok(Self {
            cert: ck.cert.der().clone(),
            key: PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()),
        })
    }

    /// Recharge le certificat depuis `dir`, ou le génère et l'y enregistre.
    pub fn load_or_generate(dir: &Path) -> Result<Self> {
        let cert_path = dir.join(CERT_FILE);
        let key_path = dir.join(KEY_FILE);
        if cert_path.exists() && key_path.exists() {
            return Ok(Self {
                cert: CertificateDer::from(std::fs::read(cert_path)?),
                key: PrivatePkcs8KeyDer::from(std::fs::read(key_path)?),
            });
        }
        std::fs::create_dir_all(dir)?;
        let generated = Self::generate()?;
        write_private(&key_path, generated.key.secret_pkcs8_der())?;
        std::fs::write(cert_path, generated.cert.as_ref())?;
        Ok(generated)
    }

    pub fn pin(&self) -> ServerPin {
        ServerPin::of(self.cert.as_ref())
    }

    pub fn quic_server_config(&self) -> Result<quinn::ServerConfig> {
        let mut tls = rustls::ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(
                vec![self.cert.clone()],
                PrivateKeyDer::Pkcs8(self.key.clone_key()),
            )?;
        tls.alpn_protocols = vec![ALPN.to_vec()];
        let crypto = QuicServerConfig::try_from(tls)
            .map_err(|_| NetError::Protocol("suite TLS incompatible avec QUIC"))?;
        let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        cfg.transport_config(transport());
        Ok(cfg)
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)?.write_all(bytes)
}

/// Configuration client QUIC qui n'accepte que le serveur d'empreinte `pin`.
pub fn quic_client_config(pin: ServerPin) -> Result<quinn::ClientConfig> {
    client_config(Some(pin), ALPN)
}

/// Configuration serveur QUIC d'un pair qui accepte les connexions directes.
///
/// Le certificat est éphémère et n'est pas vérifié par l'autre pair : TLS ne
/// sert ici que de transport. L'authentification mutuelle des pairs est faite
/// par le handshake Noise qui suit, avec leurs identités d'appareil.
pub fn p2p_server_config() -> Result<quinn::ServerConfig> {
    let cert = ServerCert::generate()?;
    let mut tls = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert], PrivateKeyDer::Pkcs8(cert.key))?;
    tls.alpn_protocols = vec![P2P_ALPN.to_vec()];
    let crypto = QuicServerConfig::try_from(tls)
        .map_err(|_| NetError::Protocol("suite TLS incompatible avec QUIC"))?;
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    cfg.transport_config(transport());
    Ok(cfg)
}

/// Configuration client QUIC d'une connexion directe vers un pair (voir
/// [`p2p_server_config`] : l'authentification est faite par Noise).
pub fn p2p_client_config() -> Result<quinn::ClientConfig> {
    client_config(None, P2P_ALPN)
}

fn client_config(pin: Option<ServerPin>, alpn: &[u8]) -> Result<quinn::ClientConfig> {
    let provider = provider();
    let verifier = Arc::new(PinnedVerifier {
        pin,
        provider: provider.clone(),
    });
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    tls.alpn_protocols = vec![alpn.to_vec()];
    let crypto = QuicClientConfig::try_from(tls)
        .map_err(|_| NetError::Protocol("suite TLS incompatible avec QUIC"))?;
    let mut cfg = quinn::ClientConfig::new(Arc::new(crypto));
    cfg.transport_config(transport());
    Ok(cfg)
}

/// Vérifie l'empreinte du certificat (si `pin`), puis la signature TLS 1.3
/// normalement.
#[derive(Debug)]
struct PinnedVerifier {
    pin: Option<ServerPin>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if self
            .pin
            .is_none_or(|pin| ServerPin::of(end_entity.as_ref()) == pin)
        {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Ouvre une connexion QUIC vers un serveur épinglé. L'`Endpoint` retourné
/// doit rester en vie aussi longtemps que la connexion.
pub async fn connect(
    addr: std::net::SocketAddr,
    pin: ServerPin,
) -> Result<(quinn::Endpoint, quinn::Connection)> {
    let endpoint = endpoint_for(addr, None)?;
    let conn = connect_on(&endpoint, addr, pin).await?;
    Ok((endpoint, conn))
}

/// Endpoint QUIC sur un port UDP éphémère de la famille d'adresses de
/// `peer`. Avec `server`, il accepte aussi les connexions entrantes.
pub fn endpoint_for(
    peer: std::net::SocketAddr,
    server: Option<quinn::ServerConfig>,
) -> Result<quinn::Endpoint> {
    let bind: std::net::SocketAddr = if peer.is_ipv6() {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let socket = std::net::UdpSocket::bind(bind)?;
    let runtime =
        quinn::default_runtime().ok_or(NetError::Protocol("runtime asynchrone introuvable"))?;
    Ok(quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        server,
        socket,
        runtime,
    )?)
}

/// Connexion vers le serveur d'empreinte `pin` depuis un endpoint existant.
pub async fn connect_on(
    endpoint: &quinn::Endpoint,
    addr: std::net::SocketAddr,
    pin: ServerPin,
) -> Result<quinn::Connection> {
    Ok(endpoint
        .connect_with(quic_client_config(pin)?, addr, SERVER_NAME)?
        .await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_hex_roundtrip() {
        let pin = ServerPin::of(b"certificat");
        let parsed: ServerPin = pin.to_string().parse().unwrap();
        assert_eq!(pin, parsed);
        assert!("abc".parse::<ServerPin>().is_err());
        assert!("zz".repeat(32).parse::<ServerPin>().is_err());
    }
}
