//! Conversions entre identités Creamote et messages protobuf, et preuve de
//! possession liée à la connexion.

use creamote_crypto::{DeviceIdentity, PublicIdentity};
use creamote_proto::common::v1::DeviceIdentity as ProtoIdentity;

use crate::{NetError, Result};

const EXPORTER_LABEL: &[u8] = b"EXPORTER-creamote-register";
const PROOF_CONTEXT: &[u8] = b"creamote/register/v1";

pub fn to_proto(id: &PublicIdentity) -> ProtoIdentity {
    ProtoIdentity {
        signing_public_key: id.signing_key().to_vec(),
        noise_static_key: id.noise_static().to_vec(),
        noise_key_signature: id.binding().to_vec(),
    }
}

/// Décode **et vérifie** une identité reçue.
pub fn from_proto(p: &ProtoIdentity) -> Result<PublicIdentity> {
    Ok(PublicIdentity::from_parts(
        &p.signing_public_key,
        &p.noise_static_key,
        &p.noise_key_signature,
    )?)
}

fn proof_message(conn: &quinn::Connection) -> Result<Vec<u8>> {
    let mut exporter = [0u8; 32];
    conn.export_keying_material(&mut exporter, EXPORTER_LABEL, &[])
        .map_err(|_| NetError::Protocol("exporteur TLS indisponible"))?;
    Ok([PROOF_CONTEXT, exporter.as_slice()].concat())
}

/// Signe la preuve d'enregistrement pour cette connexion.
pub fn register_proof(conn: &quinn::Connection, id: &DeviceIdentity) -> Result<Vec<u8>> {
    Ok(id.sign(&proof_message(conn)?).to_bytes().to_vec())
}

/// Vérifie la preuve d'enregistrement côté serveur.
pub fn verify_register_proof(
    conn: &quinn::Connection,
    id: &PublicIdentity,
    proof: &[u8],
) -> Result<bool> {
    Ok(id.verify(&proof_message(conn)?, proof))
}
