//! Outils sur les flux H.264 Annex B (codes de début `00 00 01`).

/// Unités NAL d'un flux Annex B (sans les codes de début).
pub fn nal_units(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut starts = Vec::new();
    let mut i = 0;
    while i + 3 <= data.len() {
        if data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1 {
            starts.push(i + 3);
            i += 3;
        } else {
            i += 1;
        }
    }
    let ends: Vec<usize> = starts
        .iter()
        .skip(1)
        .map(|&s| {
            // Retire le code de début suivant (3 ou 4 octets).
            let mut e = s - 3;
            if e > 0 && data[e - 1] == 0 {
                e -= 1;
            }
            e
        })
        .chain(std::iter::once(data.len()))
        .collect();
    starts
        .into_iter()
        .zip(ends)
        .map(move |(s, e)| &data[s..e.max(s)])
}

/// Type d'une unité NAL (5 bits de poids faible du premier octet).
pub fn nal_type(nal: &[u8]) -> u8 {
    nal.first().map_or(0, |b| b & 0x1f)
}

pub const NAL_IDR: u8 = 5;
pub const NAL_SPS: u8 = 7;

pub fn is_keyframe(data: &[u8]) -> bool {
    nal_units(data).any(|n| nal_type(n) == NAL_IDR)
}

pub fn has_sps(data: &[u8]) -> bool {
    nal_units(data).any(|n| nal_type(n) == NAL_SPS)
}

/// Convertit des NAL préfixées par leur longueur (AVCC, `len_size` octets)
/// en Annex B, à la suite de `out`.
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
pub fn avcc_to_annexb(data: &[u8], len_size: usize, out: &mut Vec<u8>) -> bool {
    let mut i = 0;
    while i + len_size <= data.len() {
        let len = data[i..i + len_size]
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
        i += len_size;
        if i + len > data.len() {
            return false;
        }
        out.extend_from_slice(&[0, 0, 0, 1]);
        out.extend_from_slice(&data[i..i + len]);
        i += len;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_and_classifies() {
        let s = [
            0, 0, 0, 1, 0x67, 1, 2, 0, 0, 1, 0x68, 3, 0, 0, 0, 1, 0x65, 9,
        ];
        let n: Vec<_> = nal_units(&s).collect();
        assert_eq!(n, [&[0x67, 1, 2][..], &[0x68, 3], &[0x65, 9]]);
        assert!(is_keyframe(&s) && has_sps(&s));
        assert!(!is_keyframe(&[0, 0, 1, 0x41, 7]));
    }

    #[test]
    fn avcc_conversion() {
        let mut out = Vec::new();
        assert!(avcc_to_annexb(
            &[0, 0, 0, 2, 0x65, 1, 0, 0, 0, 1, 0x41],
            4,
            &mut out
        ));
        assert_eq!(out, [0, 0, 0, 1, 0x65, 1, 0, 0, 0, 1, 0x41]);
        assert!(!avcc_to_annexb(&[0, 0, 0, 9, 1], 4, &mut out));
    }
}
