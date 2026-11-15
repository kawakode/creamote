//! Host Creamote.
//!
//! M0 : crée ou recharge l'identité de l'appareil et affiche son ID.
//! Le stockage dans le coffre de l'OS (DPAPI, Keychain, libsecret) remplacera
//! le fichier dans un prochain milestone.
//!
//! Usage : `creamote-host [--identity-file <chemin>]`

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use creamote_crypto::DeviceIdentity;

fn main() -> ExitCode {
    let path = match parse_args() {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("{msg}\nusage : creamote-host [--identity-file <chemin>]");
            return ExitCode::from(2);
        }
    };
    match load_or_create(&path) {
        Ok((id, created)) => {
            let state = if created { "créée" } else { "chargée" };
            println!("Identité {state} : {}", path.display());
            println!("ID de l'appareil : {}", id.device_id());
            println!("Empreinte        : {}", id.public().fingerprint());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("erreur : {e}");
            ExitCode::FAILURE
        }
    }
}

fn parse_args() -> Result<PathBuf, String> {
    let mut args = std::env::args().skip(1);
    let mut path = PathBuf::from("creamote-host.identity");
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--identity-file" => {
                path = args
                    .next()
                    .ok_or("--identity-file attend un chemin")?
                    .into();
            }
            other => return Err(format!("argument inconnu : {other}")),
        }
    }
    Ok(path)
}

fn load_or_create(path: &Path) -> Result<(DeviceIdentity, bool), Box<dyn std::error::Error>> {
    if path.exists() {
        let bytes = fs::read(path)?;
        return Ok((DeviceIdentity::from_secret_bytes(&bytes)?, false));
    }
    let id = DeviceIdentity::generate();
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)?.write_all(&*id.to_secret_bytes())?;
    Ok((id, true))
}
