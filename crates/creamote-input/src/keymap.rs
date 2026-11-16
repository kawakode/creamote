//! Correspondance entre usages USB HID (page clavier 0x07), noms
//! `KeyboardEvent.code` du navigateur et codes natifs de chaque OS.

/// Code absent pour cet OS.
pub(crate) const NONE: u16 = 0xFFFF;
/// Pause n'a pas de scancode simple (séquence E1) : touche virtuelle.
pub(crate) const PAUSE: u16 = 0xE11D;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Key {
    /// Usage HID (page 0x07).
    pub hid: u32,
    /// Code evdev Linux (code X11 = evdev + 8).
    pub evdev: u16,
    /// Scancode PC jeu 1 ; `0xE0xx` pour les touches étendues.
    pub set1: u16,
    /// Code de touche virtuel macOS (`kVK_*`), position physique.
    pub mac: u16,
    /// Nom `KeyboardEvent.code` (W3C UI Events).
    pub code: &'static str,
}

include!("keymap_table.rs");

pub fn by_hid(hid: u32) -> Option<&'static Key> {
    KEYMAP
        .binary_search_by_key(&hid, |k| k.hid)
        .ok()
        .map(|i| &KEYMAP[i])
}

pub fn by_code(code: &str) -> Option<&'static Key> {
    KEYMAP.iter().find(|k| k.code == code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_sorted_and_unique() {
        assert!(KEYMAP.windows(2).all(|w| w[0].hid < w[1].hid));
        let mut codes: Vec<_> = KEYMAP.iter().map(|k| k.code).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), KEYMAP.len());
    }

    #[test]
    fn lookups() {
        let a = by_code("KeyA").unwrap();
        assert_eq!((a.hid, a.evdev, a.set1, a.mac), (0x04, 30, 0x1E, 0x00));
        assert_eq!(by_hid(0x52).unwrap().code, "ArrowUp");
        assert_eq!(by_hid(0x52).unwrap().set1, 0xE048);
        assert!(by_hid(0x03).is_none());
    }

    /// Le client (ui/keymap.js) doit envoyer les mêmes usages HID.
    #[test]
    fn client_keymap_matches() {
        let js = include_str!("../../../client/ui/keymap.js");
        for k in KEYMAP {
            let entry = format!("{}: 0x{:02x},", k.code, k.hid);
            assert!(
                js.contains(&entry),
                "client/ui/keymap.js : {entry} manquant"
            );
        }
    }
}
