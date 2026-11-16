//! Chemins reçus de l'autre pair : validation stricte avant toute écriture.

use std::path::{Path, PathBuf};

/// Profondeur maximale d'un chemin reçu.
pub const MAX_DEPTH: usize = 32;
/// Longueur maximale d'un chemin reçu, en octets.
pub const MAX_LEN: usize = 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("chemin refusé : {0}")]
pub struct BadPath(pub &'static str);

/// Noms réservés par Windows, quelle que soit l'extension.
const RESERVED: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Convertit un chemin relatif reçu (séparateur « / ») en chemin local sûr :
/// ni absolu, ni « .. », ni caractère interdit sur l'un des OS cibles, pour
/// qu'il reste sous le dossier de destination sur toutes les plateformes.
pub fn sanitize(path: &str) -> Result<PathBuf, BadPath> {
    if path.is_empty() || path.len() > MAX_LEN {
        return Err(BadPath("longueur"));
    }
    let mut out = PathBuf::new();
    let mut depth = 0;
    for part in path.split('/') {
        match part {
            "" | "." => continue,
            ".." => return Err(BadPath("remontée « .. »")),
            _ => {}
        }
        if part
            .chars()
            .any(|c| c.is_control() || matches!(c, '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|'))
        {
            return Err(BadPath("caractère interdit"));
        }
        if part.ends_with(['.', ' ']) {
            return Err(BadPath("point ou espace final"));
        }
        let stem = part.split('.').next().unwrap_or(part);
        if RESERVED.iter().any(|r| r.eq_ignore_ascii_case(stem)) {
            return Err(BadPath("nom réservé"));
        }
        depth += 1;
        if depth > MAX_DEPTH {
            return Err(BadPath("profondeur"));
        }
        out.push(part);
    }
    if depth == 0 {
        return Err(BadPath("chemin vide"));
    }
    Ok(out)
}

/// Premier chemin libre parmi `dir/rel`, `dir/rel (1)`, `dir/rel (2)`… (le
/// suffixe est inséré avant l'extension). Un fichier existant n'est jamais
/// écrasé.
pub fn unique(dir: &Path, rel: &Path) -> PathBuf {
    let first = dir.join(rel);
    if !first.exists() {
        return first;
    }
    let stem = first
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let ext = first
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    for n in 1.. {
        let candidate = first.with_file_name(format!("{stem} ({n}){ext}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    unreachable!("suite infinie")
}

/// Chemin relatif à envoyer pour un fichier local : `base` (dossier ou
/// fichier choisi par l'utilisateur) détermine la racine.
pub fn relative_name(base: &Path, file: &Path) -> Option<String> {
    let root = base.parent().unwrap_or(Path::new(""));
    let rel = file.strip_prefix(root).ok()?;
    let parts: Option<Vec<&str>> = rel.components().map(|c| c.as_os_str().to_str()).collect();
    Some(parts?.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plain_relative_paths() {
        assert_eq!(sanitize("a/b.txt").unwrap(), Path::new("a").join("b.txt"));
        assert_eq!(sanitize("./x//y").unwrap(), Path::new("x").join("y"));
        assert_eq!(sanitize("été.png").unwrap(), PathBuf::from("été.png"));
    }

    #[test]
    fn rejects_escapes_and_platform_traps() {
        for bad in [
            "",
            "..",
            "a/../b",
            "/",
            "C:/x",
            "a\\b",
            "con",
            "dir/NUL.txt",
            "a ",
            "a.",
            "x\0y",
            "tab\there",
        ] {
            assert!(sanitize(bad).is_err(), "{bad:?} aurait dû être refusé");
        }
        assert!(sanitize(&"a/".repeat(MAX_DEPTH + 1)).is_err());
        // « /etc/passwd » devient « etc/passwd », relatif à la destination.
        assert_eq!(
            sanitize("/etc/passwd").unwrap(),
            Path::new("etc").join("passwd")
        );
    }

    #[test]
    fn unique_never_overwrites() {
        let dir = std::env::temp_dir().join(format!("creamote-unique-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let rel = Path::new("f.txt");
        assert_eq!(unique(&dir, rel), dir.join("f.txt"));
        std::fs::write(dir.join("f.txt"), b"1").unwrap();
        assert_eq!(unique(&dir, rel), dir.join("f (1).txt"));
        std::fs::write(dir.join("f (1).txt"), b"2").unwrap();
        assert_eq!(unique(&dir, rel), dir.join("f (2).txt"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn relative_names_keep_the_chosen_folder() {
        let base = Path::new("home").join("u").join("photos");
        let file = base.join("2026").join("a.jpg");
        assert_eq!(relative_name(&base, &file).unwrap(), "photos/2026/a.jpg");
        let single = Path::new("home").join("u").join("doc.pdf");
        assert_eq!(relative_name(&single, &single).unwrap(), "doc.pdf");
    }
}
