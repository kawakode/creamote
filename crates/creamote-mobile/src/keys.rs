//! Touches physiques (usages USB HID, comme sur les autres plateformes) et
//! codes `KeyEvent.KEYCODE_*` d'Android, dans les deux sens : clavier
//! matériel du viewer Android, injection sur le host Android.

use creamote_input::{by_code, by_hid};

/// `KeyboardEvent.code` → `android.view.KeyEvent.KEYCODE_*`.
const ANDROID: &[(&str, i32)] = &[
    ("KeyA", 29),
    ("KeyB", 30),
    ("KeyC", 31),
    ("KeyD", 32),
    ("KeyE", 33),
    ("KeyF", 34),
    ("KeyG", 35),
    ("KeyH", 36),
    ("KeyI", 37),
    ("KeyJ", 38),
    ("KeyK", 39),
    ("KeyL", 40),
    ("KeyM", 41),
    ("KeyN", 42),
    ("KeyO", 43),
    ("KeyP", 44),
    ("KeyQ", 45),
    ("KeyR", 46),
    ("KeyS", 47),
    ("KeyT", 48),
    ("KeyU", 49),
    ("KeyV", 50),
    ("KeyW", 51),
    ("KeyX", 52),
    ("KeyY", 53),
    ("KeyZ", 54),
    ("Digit0", 7),
    ("Digit1", 8),
    ("Digit2", 9),
    ("Digit3", 10),
    ("Digit4", 11),
    ("Digit5", 12),
    ("Digit6", 13),
    ("Digit7", 14),
    ("Digit8", 15),
    ("Digit9", 16),
    ("Enter", 66),
    ("Escape", 111),
    ("Backspace", 67),
    ("Tab", 61),
    ("Space", 62),
    ("Minus", 69),
    ("Equal", 70),
    ("BracketLeft", 71),
    ("BracketRight", 72),
    ("Backslash", 73),
    ("Semicolon", 74),
    ("Quote", 75),
    ("Backquote", 68),
    ("Comma", 55),
    ("Period", 56),
    ("Slash", 76),
    ("CapsLock", 115),
    ("F1", 131),
    ("F2", 132),
    ("F3", 133),
    ("F4", 134),
    ("F5", 135),
    ("F6", 136),
    ("F7", 137),
    ("F8", 138),
    ("F9", 139),
    ("F10", 140),
    ("F11", 141),
    ("F12", 142),
    ("PrintScreen", 120),
    ("ScrollLock", 116),
    ("Pause", 121),
    ("Insert", 124),
    ("Home", 122),
    ("PageUp", 92),
    ("Delete", 112),
    ("End", 123),
    ("PageDown", 93),
    ("ArrowRight", 22),
    ("ArrowLeft", 21),
    ("ArrowDown", 20),
    ("ArrowUp", 19),
    ("NumLock", 143),
    ("NumpadDivide", 154),
    ("NumpadMultiply", 155),
    ("NumpadSubtract", 156),
    ("NumpadAdd", 157),
    ("NumpadEnter", 160),
    ("Numpad0", 144),
    ("Numpad1", 145),
    ("Numpad2", 146),
    ("Numpad3", 147),
    ("Numpad4", 148),
    ("Numpad5", 149),
    ("Numpad6", 150),
    ("Numpad7", 151),
    ("Numpad8", 152),
    ("Numpad9", 153),
    ("NumpadDecimal", 158),
    ("NumpadEqual", 161),
    ("ContextMenu", 82),
    ("AudioVolumeMute", 164),
    ("AudioVolumeUp", 24),
    ("AudioVolumeDown", 25),
    ("IntlRo", 217),
    ("IntlYen", 216),
    ("KanaMode", 218),
    ("Convert", 214),
    ("NonConvert", 213),
    ("ControlLeft", 113),
    ("ShiftLeft", 59),
    ("AltLeft", 57),
    ("MetaLeft", 117),
    ("ControlRight", 114),
    ("ShiftRight", 60),
    ("AltRight", 58),
    ("MetaRight", 118),
];

/// Code Android de la touche physique `hid` (`None` : pas d'équivalent).
#[uniffi::export]
pub fn android_keycode(hid: u32) -> Option<i32> {
    let code = by_hid(hid)?.code;
    ANDROID.iter().find(|(c, _)| *c == code).map(|(_, k)| *k)
}

/// Usage HID d'une touche du clavier matériel du viewer Android.
#[uniffi::export]
pub fn hid_from_android_keycode(keycode: i32) -> Option<u32> {
    let (code, _) = ANDROID.iter().find(|(_, k)| *k == keycode)?;
    by_code(code).map(|k| k.hid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_is_known_and_unique() {
        for (code, _) in ANDROID {
            assert!(by_code(code).is_some(), "{code} absent de la table HID");
        }
        let mut keycodes: Vec<_> = ANDROID.iter().map(|(_, k)| *k).collect();
        keycodes.sort_unstable();
        keycodes.dedup();
        assert_eq!(keycodes.len(), ANDROID.len());
    }

    #[test]
    fn roundtrip() {
        assert_eq!(android_keycode(0x04), Some(29)); // A
        assert_eq!(android_keycode(0x28), Some(66)); // Entrée
        assert_eq!(hid_from_android_keycode(67), Some(0x2A)); // Retour arrière
        assert_eq!(android_keycode(0x68), None); // F13
        for (_, k) in ANDROID {
            let hid = hid_from_android_keycode(*k).unwrap();
            assert_eq!(android_keycode(hid), Some(*k));
        }
    }
}
