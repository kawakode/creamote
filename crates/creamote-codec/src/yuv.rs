//! Conversion BGRA → YUV 4:2:0 (BT.709, plage limitée), pour les encodeurs
//! qui ne convertissent pas eux-mêmes (openh264, Media Foundation).

use creamote_capture::Frame;

/// Taille encodable : les encodeurs H.264 exigent des dimensions paires.
pub fn even_dims(width: u32, height: u32) -> (u32, u32) {
    (width & !1, height & !1)
}

#[inline]
fn y_of(b: i32, g: i32, r: i32) -> u8 {
    ((47 * r + 157 * g + 16 * b + 128) >> 8).wrapping_add(16) as u8
}

#[inline]
fn uv_of(b: i32, g: i32, r: i32) -> (u8, u8) {
    let u = ((-26 * r - 86 * g + 112 * b + 128) >> 8) + 128;
    let v = ((112 * r - 102 * g - 10 * b + 128) >> 8) + 128;
    (u.clamp(0, 255) as u8, v.clamp(0, 255) as u8)
}

/// Parcourt l'image par blocs 2×2 : `luma(x, y, Y)` puis `chroma(cx, cy, U, V)`.
fn convert(
    frame: &Frame,
    mut luma: impl FnMut(usize, usize, u8),
    mut chroma: impl FnMut(usize, usize, u8, u8),
) {
    let (w, h) = even_dims(frame.width, frame.height);
    let (w, h) = (w as usize, h as usize);
    for cy in 0..h / 2 {
        let r0 = &frame.data[2 * cy * frame.stride..];
        let r1 = &frame.data[(2 * cy + 1) * frame.stride..];
        for cx in 0..w / 2 {
            let (mut sb, mut sg, mut sr) = (0, 0, 0);
            for (row, dy) in [(r0, 0), (r1, 1)] {
                for dx in 0..2 {
                    let x = 2 * cx + dx;
                    let p = &row[x * 4..x * 4 + 3];
                    let (b, g, r) = (i32::from(p[0]), i32::from(p[1]), i32::from(p[2]));
                    luma(x, 2 * cy + dy, y_of(b, g, r));
                    sb += b;
                    sg += g;
                    sr += r;
                }
            }
            let (u, v) = uv_of((sb + 2) >> 2, (sg + 2) >> 2, (sr + 2) >> 2);
            chroma(cx, cy, u, v);
        }
    }
}

/// Plans I420 compacts (Y puis U puis V) aux dimensions paires.
pub struct I420 {
    pub width: usize,
    pub height: usize,
    pub y: Vec<u8>,
    pub u: Vec<u8>,
    pub v: Vec<u8>,
}

pub fn to_i420(frame: &Frame) -> I420 {
    let (w, h) = even_dims(frame.width, frame.height);
    let (w, h) = (w as usize, h as usize);
    let mut y = vec![0; w * h];
    let mut u = vec![0; w * h / 4];
    let mut v = vec![0; w * h / 4];
    convert(
        frame,
        |px, py, l| y[py * w + px] = l,
        |cx, cy, cu, cv| {
            u[cy * w / 2 + cx] = cu;
            v[cy * w / 2 + cx] = cv;
        },
    );
    I420 {
        width: w,
        height: h,
        y,
        u,
        v,
    }
}

/// NV12 compact (plan Y puis plan UV entrelacé) aux dimensions paires.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
pub fn to_nv12(frame: &Frame) -> Vec<u8> {
    let (w, h) = even_dims(frame.width, frame.height);
    let (w, h) = (w as usize, h as usize);
    let mut out = vec![0; w * h * 3 / 2];
    let (y, uv) = out.split_at_mut(w * h);
    convert(
        frame,
        |px, py, l| y[py * w + px] = l,
        |cx, cy, cu, cv| {
            uv[cy * w + 2 * cx] = cu;
            uv[cy * w + 2 * cx + 1] = cv;
        },
    );
    out
}

/// I420 (plans de pas quelconques) → RGBA compact, BT.709 plage limitée.
#[allow(clippy::too_many_arguments)]
pub fn i420_to_rgba(
    width: usize,
    height: usize,
    y: &[u8],
    u: &[u8],
    v: &[u8],
    y_stride: usize,
    uv_stride: usize,
    out: &mut [u8],
) {
    for row in 0..height {
        for col in 0..width {
            let yy = (i32::from(y[row * y_stride + col]) - 16) * 298;
            let ci = (row / 2) * uv_stride + col / 2;
            let (cu, cv) = (i32::from(u[ci]) - 128, i32::from(v[ci]) - 128);
            let r = (yy + 459 * cv + 128) >> 8;
            let g = (yy - 55 * cu - 136 * cv + 128) >> 8;
            let b = (yy + 541 * cu + 128) >> 8;
            let o = (row * width + col) * 4;
            out[o] = r.clamp(0, 255) as u8;
            out[o + 1] = g.clamp(0, 255) as u8;
            out[o + 2] = b.clamp(0, 255) as u8;
            out[o + 3] = 255;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_colors() {
        // Noir, blanc, rouge pur en BT.709 plage limitée.
        assert_eq!(y_of(0, 0, 0), 16);
        assert_eq!(y_of(255, 255, 255), 235);
        assert_eq!(uv_of(255, 255, 255), (128, 128));
        let red = Frame::solid(2, 2, [0, 0, 255, 255]);
        let i = to_i420(&red);
        assert_eq!((i.y[0], i.u[0], i.v[0]), (63, 102, 240));
    }

    #[test]
    fn rgba_roundtrip_is_close() {
        for bgra in [
            [10, 200, 30, 255],
            [255, 255, 255, 255],
            [0, 0, 0, 255],
            [40, 90, 220, 255],
        ] {
            let i = to_i420(&Frame::solid(2, 2, bgra));
            let mut out = [0u8; 16];
            i420_to_rgba(2, 2, &i.y, &i.u, &i.v, 2, 1, &mut out);
            for (k, c) in [(0, 2), (1, 1), (2, 0)] {
                assert!(out[k].abs_diff(bgra[c]) <= 3, "{bgra:?} -> {out:?}");
            }
        }
    }

    #[test]
    fn odd_sizes_are_cropped_and_nv12_interleaves() {
        let f = Frame::solid(5, 3, [255, 255, 255, 255]);
        let i = to_i420(&f);
        assert_eq!((i.width, i.height, i.y.len(), i.u.len()), (4, 2, 8, 2));
        let nv = to_nv12(&f);
        assert_eq!(nv.len(), 12);
        assert_eq!(&nv[8..], &[128, 128, 128, 128]);
    }
}
