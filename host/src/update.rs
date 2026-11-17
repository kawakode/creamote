//! Mise à jour automatique du host installé.
//!
//! Chaque release publie `host-latest.json`, signé (`host-latest.json.sig`)
//! avec la clé de mise à jour du projet (format minisign, le même que la mise
//! à jour du client Tauri). Le manifeste donne, pour chaque type de paquet,
//! son URL et son empreinte SHA-256. Le host :
//!
//! 1. télécharge le manifeste et vérifie sa signature avec la clé publique
//!    intégrée à la compilation (`CREAMOTE_UPDATE_PUBKEY`) ou celle de la
//!    configuration (`update_pubkey`) ;
//! 2. n'accepte qu'une version strictement plus récente que la sienne (pas
//!    de retour en arrière, même avec un ancien manifeste signé) ;
//! 3. télécharge le paquet de sa plateforme, vérifie son empreinte, puis
//!    lance l'installeur du système (`msiexec`, `installer`, `dpkg`, `rpm`).
//!
//! La vérification tourne avec les droits d'administration : dans le service
//! sous Windows, par un démon launchd sous macOS et un timer systemd sous
//! Linux (`creamote-host update`), toutes les 6 heures.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use base64::Engine;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::config::HostConfig;

/// Manifeste par défaut : celui de la dernière release publiée.
pub const DEFAULT_URL: &str =
    "https://github.com/kawakode/creamote/releases/latest/download/host-latest.json";
/// Clé publique de mise à jour intégrée à la compilation (format Tauri :
/// base64 du fichier `.pub` de minisign).
const BUILTIN_PUBKEY: Option<&str> = option_env!("CREAMOTE_UPDATE_PUBKEY");
/// Intervalle entre deux vérifications (service Windows ; ailleurs, le
/// timer systemd ou le démon launchd).
#[cfg_attr(not(windows), allow(dead_code))]
pub const INTERVAL: Duration = Duration::from_secs(6 * 3600);
/// Taille maximale d'un paquet téléchargé.
const MAX_PACKAGE: u64 = 512 * 1024 * 1024;
const MAX_MANIFEST: usize = 64 * 1024;

#[derive(Debug, Deserialize)]
pub struct Manifest {
    pub version: String,
    pub assets: HashMap<String, Asset>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Asset {
    pub url: String,
    pub sha256: String,
}

/// Réglages de mise à jour : clé publique et URL du manifeste.
pub struct Updater {
    pubkey: minisign_verify::PublicKey,
    url: String,
}

impl Updater {
    /// `None` si la mise à jour est désactivée (option `auto_update =
    /// false`, ou aucune clé publique connue).
    pub fn from_config(cfg: &HostConfig) -> anyhow::Result<Option<Self>> {
        if cfg.auto_update == Some(false) {
            return Ok(None);
        }
        let builtin = BUILTIN_PUBKEY.filter(|k| !k.trim().is_empty());
        let Some(key) = cfg.update_pubkey.as_deref().or(builtin) else {
            return Ok(None);
        };
        Ok(Some(Self {
            pubkey: decode_pubkey(key)?,
            url: cfg.update_url.clone().unwrap_or_else(|| DEFAULT_URL.into()),
        }))
    }

    /// Vérifie s'il existe une version plus récente pour cette plateforme.
    pub async fn check(&self, client: &reqwest::Client) -> anyhow::Result<Option<(String, Asset)>> {
        let manifest = fetch(client, &self.url, MAX_MANIFEST as u64).await?;
        let sig = fetch(client, &format!("{}.sig", self.url), 4096).await?;
        let m = verify_manifest(&self.pubkey, &manifest, &sig)?;
        let Some(kind) = package_kind() else {
            anyhow::bail!("pas de paquet connu pour cette plateforme");
        };
        if !is_newer(&m.version, env!("CARGO_PKG_VERSION")) {
            return Ok(None);
        }
        let asset = m
            .assets
            .get(kind)
            .with_context(|| format!("version {} sans paquet {kind}", m.version))?;
        Ok(Some((m.version, asset.clone())))
    }
}

/// Accepte une clé au format Tauri (base64 du fichier `.pub`), le contenu du
/// fichier `.pub` ou la seule ligne de clé.
fn decode_pubkey(key: &str) -> anyhow::Result<minisign_verify::PublicKey> {
    let key = key.trim();
    let text = base64::engine::general_purpose::STANDARD
        .decode(key)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .filter(|t| t.contains('\n'));
    let decoded = match text {
        Some(t) => minisign_verify::PublicKey::decode(&t),
        None if key.contains('\n') => minisign_verify::PublicKey::decode(key),
        None => minisign_verify::PublicKey::from_base64(key),
    };
    decoded.map_err(|e| anyhow::anyhow!("clé publique de mise à jour invalide : {e}"))
}

/// Vérifie la signature du manifeste (format Tauri : base64 du fichier
/// `.minisig`, ou le fichier lui-même) puis le lit.
pub fn verify_manifest(
    pubkey: &minisign_verify::PublicKey,
    manifest: &[u8],
    sig: &[u8],
) -> anyhow::Result<Manifest> {
    let sig = std::str::from_utf8(sig)
        .context("signature illisible")?
        .trim();
    let text = base64::engine::general_purpose::STANDARD
        .decode(sig)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_else(|| sig.to_owned());
    let sig = minisign_verify::Signature::decode(&text)
        .map_err(|e| anyhow::anyhow!("signature invalide : {e}"))?;
    pubkey
        .verify(manifest, &sig, true)
        .map_err(|e| anyhow::anyhow!("signature du manifeste refusée : {e}"))?;
    serde_json::from_slice(manifest).context("manifeste illisible")
}

/// `a` est-elle strictement plus récente que `b` ? Versions `X.Y.Z`, avec
/// suffixe éventuel (`-rc.1`) ignoré pour la comparaison, une préversion
/// n'étant jamais proposée face à la même version finale.
pub fn is_newer(a: &str, b: &str) -> bool {
    fn parse(v: &str) -> Option<([u64; 3], bool)> {
        let v = v.trim().trim_start_matches('v');
        let (core, pre) = match v.split_once('-') {
            Some((c, _)) => (c, true),
            None => (v, false),
        };
        let mut it = core.split('.').map(|p| p.parse::<u64>().ok());
        let n = [it.next()??, it.next()??, it.next()??];
        it.next().is_none().then_some((n, pre))
    }
    match (parse(a), parse(b)) {
        (Some((na, pa)), Some((nb, pb))) => na > nb || (na == nb && pb && !pa),
        _ => false,
    }
}

/// Type de paquet installé sur cette machine.
pub fn package_kind() -> Option<&'static str> {
    if cfg!(all(windows, target_arch = "x86_64")) {
        Some("windows-x86_64-msi")
    } else if cfg!(target_os = "macos") {
        Some("darwin-universal-pkg")
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        if Path::new("/usr/bin/dpkg").exists() {
            Some("linux-x86_64-deb")
        } else if Path::new("/usr/bin/rpm").exists() {
            Some("linux-x86_64-rpm")
        } else {
            None
        }
    } else {
        None
    }
}

async fn fetch(client: &reqwest::Client, url: &str, max: u64) -> anyhow::Result<Vec<u8>> {
    let mut resp = client
        .get(url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .with_context(|| url.to_owned())?;
    anyhow::ensure!(
        resp.content_length().unwrap_or(0) <= max,
        "{url} : réponse trop grande"
    );
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        body.extend_from_slice(&chunk);
        anyhow::ensure!(body.len() as u64 <= max, "{url} : réponse trop grande");
    }
    Ok(body)
}

pub fn client() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .user_agent(concat!("creamote-host/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(600))
        .build()?)
}

/// Télécharge le paquet, vérifie son empreinte et l'installe.
pub async fn download_and_install(
    client: &reqwest::Client,
    version: &str,
    asset: &Asset,
    dir: &Path,
) -> anyhow::Result<()> {
    anyhow::ensure!(asset.url.starts_with("https://"), "URL non HTTPS refusée");
    let bytes = fetch(client, &asset.url, MAX_PACKAGE).await?;
    let digest = Sha256::digest(&bytes);
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    anyhow::ensure!(
        hex.eq_ignore_ascii_case(asset.sha256.trim()),
        "empreinte du paquet incorrecte"
    );
    std::fs::create_dir_all(dir)?;
    let ext = asset
        .url
        .rsplit('.')
        .next()
        .filter(|e| ["msi", "pkg", "deb", "rpm"].contains(e))
        .context("extension de paquet inconnue")?;
    let path = dir.join(format!("creamote-host-{version}.{ext}"));
    std::fs::write(&path, &bytes)?;
    println!(
        "Mise à jour vers {version} : installation de {}",
        path.display()
    );
    install(&path, dir)
}

fn install(path: &Path, dir: &Path) -> anyhow::Result<()> {
    use std::process::Command;
    #[cfg(windows)]
    {
        // msiexec arrête le service (donc ce processus), remplace le binaire
        // et redémarre le service : on ne l'attend pas.
        let log: PathBuf = dir.join("update-msi.log");
        Command::new("msiexec")
            .arg("/i")
            .arg(path)
            .args(["/qn", "/norestart", "/l*v"])
            .arg(log)
            .spawn()
            .context("msiexec")?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _: &Path = dir;
        let mut cmd = match path.extension().and_then(|e| e.to_str()) {
            Some("pkg") => {
                let mut c = Command::new("/usr/sbin/installer");
                c.arg("-pkg").arg(path).args(["-target", "/"]);
                c
            }
            Some("deb") => {
                let mut c = Command::new("dpkg");
                c.arg("-i").arg(path);
                c
            }
            Some("rpm") => {
                let mut c = Command::new("rpm");
                c.arg("-U").arg(path);
                c
            }
            _ => anyhow::bail!("paquet inattendu : {}", path.display()),
        };
        let status = cmd.status().with_context(|| format!("{cmd:?}"))?;
        anyhow::ensure!(status.success(), "{cmd:?} : {status}");
        let _ = std::fs::remove_file(path);
        Ok(())
    }
}

/// Dossier des paquets téléchargés.
pub fn download_dir() -> PathBuf {
    #[cfg(windows)]
    {
        crate::config::program_data().join("updates")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/var/tmp/creamote-update")
    }
}

/// `creamote-host update` : vérifie, et installe si `apply`.
pub async fn run(cfg: &HostConfig, apply: bool) -> anyhow::Result<()> {
    let Some(updater) = Updater::from_config(cfg)? else {
        println!(
            "Mise à jour automatique désactivée (auto_update = false, ou pas de clé publique)."
        );
        return Ok(());
    };
    let client = client()?;
    match updater.check(&client).await? {
        None => println!("Version {} à jour.", env!("CARGO_PKG_VERSION")),
        Some((version, asset)) if apply => {
            download_and_install(&client, &version, &asset, &download_dir()).await?
        }
        Some((version, _)) => println!("Version {version} disponible."),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> (minisign::KeyPair, minisign_verify::PublicKey) {
        let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let pk_text = kp.pk.to_box().unwrap().to_string();
        // Format Tauri : base64 du fichier `.pub`.
        let tauri = base64::engine::general_purpose::STANDARD.encode(&pk_text);
        let pk = decode_pubkey(&tauri).unwrap();
        (kp, pk)
    }

    fn sign(kp: &minisign::KeyPair, data: &[u8]) -> Vec<u8> {
        let sig = minisign::sign(None, &kp.sk, std::io::Cursor::new(data), None, None).unwrap();
        base64::engine::general_purpose::STANDARD
            .encode(sig.to_string())
            .into_bytes()
    }

    const MANIFEST: &[u8] = br#"{"version":"9.0.0","notes":"","assets":{
        "linux-x86_64-deb":{"url":"https://example.org/h.deb","sha256":"00"}}}"#;

    #[test]
    fn accepts_signed_manifest_only() {
        let (kp, pk) = keypair();
        let sig = sign(&kp, MANIFEST);
        let m = verify_manifest(&pk, MANIFEST, &sig).unwrap();
        assert_eq!(m.version, "9.0.0");
        assert_eq!(
            m.assets["linux-x86_64-deb"].url,
            "https://example.org/h.deb"
        );

        let tampered = String::from_utf8_lossy(MANIFEST).replace("9.0.0", "9.0.1");
        assert!(verify_manifest(&pk, tampered.as_bytes(), &sig).is_err());

        let (_, other) = keypair();
        assert!(verify_manifest(&other, MANIFEST, &sig).is_err());
        assert!(verify_manifest(&pk, MANIFEST, b"n'importe quoi").is_err());
    }

    #[test]
    fn compares_versions() {
        assert!(is_newer("0.2.0", "0.1.9"));
        assert!(is_newer("v1.0.0", "0.99.99"));
        assert!(is_newer("0.10.0", "0.9.0"));
        assert!(!is_newer("0.1.0", "0.1.0"));
        assert!(!is_newer("0.1.0", "0.2.0"));
        assert!(is_newer("0.2.0", "0.2.0-rc.1"));
        assert!(!is_newer("0.2.0-rc.1", "0.2.0"));
        assert!(!is_newer("0.2", "0.1.0"));
        assert!(!is_newer("abc", "0.1.0"));
    }

    #[test]
    fn disabled_without_key_or_by_config() {
        let off = HostConfig {
            auto_update: Some(false),
            ..Default::default()
        };
        assert!(Updater::from_config(&off).unwrap().is_none());
        let (kp, _) = keypair();
        let with_key = HostConfig {
            update_pubkey: Some(kp.pk.to_box().unwrap().to_string()),
            ..Default::default()
        };
        let u = Updater::from_config(&with_key).unwrap().unwrap();
        assert_eq!(u.url, DEFAULT_URL);
    }
}
