//! Configuration du host installé : fichier système écrit par l'installeur
//! ou l'outil de déploiement, et emplacements des données selon l'OS.
//!
//! Format : une option par ligne, `clé = valeur`, `#` pour les commentaires.
//!
//! ```text
//! server = relay.example.org:21400
//! server_pin = 0123…
//! # Jeton d'enrôlement (déploiement de masse) : utilisé une seule fois.
//! enroll_token = …
//! name = Poste accueil
//! relay_only = false
//! clipboard = true
//! file_transfer = true
//! auto_update = true
//! ```

use std::path::{Path, PathBuf};

use anyhow::Context;

/// Options lues dans le fichier de configuration. Les options de la ligne
/// de commande ont priorité.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HostConfig {
    pub server: Option<String>,
    pub server_pin: Option<String>,
    pub enroll_token: Option<String>,
    pub name: Option<String>,
    pub relay_only: Option<bool>,
    pub clipboard: Option<bool>,
    pub file_transfer: Option<bool>,
    pub files_dir: Option<PathBuf>,
    /// Mise à jour automatique (activée par défaut si une clé est connue).
    pub auto_update: Option<bool>,
    /// Manifeste de mise à jour (miroir interne, par exemple).
    pub update_url: Option<String>,
    /// Clé publique de mise à jour (format minisign ou Tauri), à la place de
    /// celle du projet (version recompilée par l'organisation).
    pub update_pubkey: Option<String>,
}

impl HostConfig {
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let mut c = Self::default();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim().trim_start_matches('\u{feff}');
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .with_context(|| format!("ligne {} : `clé = valeur` attendu", n + 1))?;
            let value = value.trim().trim_matches('"').to_owned();
            let flag = || -> anyhow::Result<Option<bool>> {
                match value.to_ascii_lowercase().as_str() {
                    "true" | "yes" | "1" | "oui" => Ok(Some(true)),
                    "false" | "no" | "0" | "non" => Ok(Some(false)),
                    _ => anyhow::bail!("ligne {} : true ou false attendu", n + 1),
                }
            };
            let text = || (!value.is_empty()).then(|| value.clone());
            match key.trim() {
                "server" => c.server = text(),
                "server_pin" => c.server_pin = text(),
                "enroll_token" => c.enroll_token = text(),
                "name" => c.name = text(),
                "relay_only" => c.relay_only = flag()?,
                "clipboard" => c.clipboard = flag()?,
                "file_transfer" => c.file_transfer = flag()?,
                "files_dir" => c.files_dir = text().map(PathBuf::from),
                "auto_update" => c.auto_update = flag()?,
                "update_url" => c.update_url = text(),
                "update_pubkey" => c.update_pubkey = text(),
                other => tracing::warn!("option inconnue ignorée : {other}"),
            }
        }
        Ok(c)
    }

    /// Lit `path` ; fichier absent = configuration vide.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(&text).with_context(|| path.display().to_string()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| path.display().to_string()),
        }
    }
}

/// Remplace (ou ajoute) les options `values` dans le texte d'un fichier de
/// configuration, en gardant les commentaires et les autres options.
pub fn set_options(text: &str, values: &[(&str, String)]) -> String {
    let mut out = Vec::new();
    let mut done = vec![false; values.len()];
    for line in text.lines() {
        let key = line
            .trim()
            .split_once('=')
            .filter(|_| !line.trim_start().starts_with('#'))
            .map(|(k, _)| k.trim());
        match key.and_then(|k| values.iter().position(|(name, _)| *name == k)) {
            Some(i) if done[i] => {} // doublon : supprimé
            Some(i) => {
                out.push(format!("{} = {}", values[i].0, values[i].1));
                done[i] = true;
            }
            None => out.push(line.to_owned()),
        }
    }
    for (i, (name, value)) in values.iter().enumerate() {
        if !done[i] {
            out.push(format!("{name} = {value}"));
        }
    }
    let mut text = out.join("\n");
    text.push('\n');
    text
}

/// Écrit les options dans le fichier `path` (créé s'il n'existe pas).
pub fn write_options(path: &Path, values: &[(&str, String)]) -> anyhow::Result<()> {
    let current = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e).with_context(|| path.display().to_string()),
    };
    // Valider avant d'écrire : le service doit pouvoir relire le fichier.
    let text = set_options(&current, values);
    HostConfig::parse(&text)?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("conf.tmp");
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, path).with_context(|| path.display().to_string())
}

/// Fichier de configuration système.
pub fn system_config_file() -> PathBuf {
    #[cfg(windows)]
    {
        program_data().join("host.conf")
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/Creamote/host.conf")
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        PathBuf::from("/etc/creamote/host.conf")
    }
}

/// Dossier des données du host installé (identité, enrôlement).
///
/// Windows : `%ProgramData%\Creamote`, réservé à SYSTEM et aux
/// administrateurs, car le service y lance le host pour toute la machine.
/// macOS et Linux : le host tourne dans la session de l'utilisateur (seul
/// moyen d'accéder à l'écran), ses données sont donc les siennes.
pub fn state_dir() -> PathBuf {
    #[cfg(windows)]
    {
        program_data()
    }
    #[cfg(target_os = "macos")]
    {
        home().join("Library/Application Support/Creamote")
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| home().join(".local/state"))
            .join("creamote")
    }
}

#[cfg(windows)]
pub fn program_data() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("Creamote")
}

#[cfg(unix)]
fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Nom de la machine, nom affiché par défaut à l'enrôlement.
pub fn hostname() -> Option<String> {
    let name = std::env::var("COMPUTERNAME").ok().or_else(|| {
        std::process::Command::new("hostname")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
    })?;
    let name = name.trim();
    (!name.is_empty()).then(|| name.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_options_and_comments() {
        let c = HostConfig::parse(
            "\u{feff}# déploiement\n\
             server = relay.example.org:21400\n\
             server_pin=\"abcd\"\n\
             enroll_token =\n\
             relay_only = oui\n\
             clipboard = false\n\
             inconnue = 1\n",
        )
        .unwrap();
        assert_eq!(c.server.as_deref(), Some("relay.example.org:21400"));
        assert_eq!(c.server_pin.as_deref(), Some("abcd"));
        assert_eq!(c.enroll_token, None);
        assert_eq!(c.relay_only, Some(true));
        assert_eq!(c.clipboard, Some(false));
        assert_eq!(c.file_transfer, None);
    }

    #[test]
    fn set_options_keeps_comments_and_replaces_values() {
        let text = "# en-tête\nserver = ancien:1\n# server_pin = commenté\nclipboard = false\nserver = doublon:2\n";
        let out = set_options(
            text,
            &[
                ("server", "relay.example.org:21400".into()),
                ("enroll_token", "abc".into()),
            ],
        );
        assert_eq!(
            out,
            "# en-tête\nserver = relay.example.org:21400\n# server_pin = commenté\n\
             clipboard = false\nenroll_token = abc\n"
        );
        let c = HostConfig::parse(&out).unwrap();
        assert_eq!(c.enroll_token.as_deref(), Some("abc"));
        assert_eq!(c.clipboard, Some(false));
    }

    #[test]
    fn rejects_malformed_lines() {
        assert!(HostConfig::parse("server").is_err());
        assert!(HostConfig::parse("clipboard = peut-être").is_err());
        assert_eq!(
            HostConfig::load(Path::new("/nonexistent/creamote/host.conf")).unwrap(),
            HostConfig::default()
        );
    }
}
