//! Stockage provisoire de l'identité dans un fichier (droits 0600 sous Unix).
//! Le coffre de l'OS (DPAPI, Keychain, libsecret, Keystore) le remplacera.

use std::io::Write;
use std::path::Path;

use crate::DeviceIdentity;

/// Recharge l'identité de `path`, ou en crée une. Le booléen indique une
/// création.
pub fn load_or_create(path: &Path) -> std::io::Result<(DeviceIdentity, bool)> {
    if path.exists() {
        let bytes = std::fs::read(path)?;
        let id = DeviceIdentity::from_secret_bytes(&bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        return Ok((id, false));
    }
    let id = DeviceIdentity::generate();
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)?.write_all(&*id.to_secret_bytes())?;
    Ok((id, true))
}
