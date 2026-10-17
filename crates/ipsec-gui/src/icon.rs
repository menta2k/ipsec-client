//! The application icon, drawn in code: a shield carrying a white padlock.
//!
//! One shape serves every use: the window icon, the tray (tinted by connection
//! state) and, through `build.rs`, the `.ico` embedded in the Windows
//! executable. It is rendered with 4x4 supersampling so small sizes stay smooth.
//! This file has no dependencies because `build.rs` includes it directly.

/// Brand colour of the application icon.
pub const APP: [u8; 3] = [0x1f, 0x6f, 0xeb];

// Used by build.rs and the tests, not by the app itself.
#[cfg_attr(not(test), allow(dead_code))]
/// Sizes embedded in the Windows `.ico`, covering 100-300% display scaling.
pub const ICO_SIZES: [u32; 8] = [16, 20, 24, 32, 40, 48, 64, 256];

const SS: u32 = 4;

/// Returns `size`x`size` RGBA pixels of the icon with the shield in `fill`.
pub fn render(size: u32, fill: [u8; 3]) -> Vec<u8> {
    let mut px = Vec::with_capacity((size * size * 4) as usize);
    let step = 1.0 / (size * SS) as f32;
    for y in 0..size {
        for x in 0..size {
            // Accumulate premultiplied colour over the subsamples.
            let (mut r, mut g, mut b, mut a) = (0.0f32, 0.0f32, 0.0f32, 0.0f32);
            for sy in 0..SS {
                for sx in 0..SS {
                    let u = ((x * SS + sx) as f32 + 0.5) * step;
                    let v = ((y * SS + sy) as f32 + 0.5) * step;
                    if let Some(c) = sample(u, v, fill) {
                        r += c[0] as f32;
                        g += c[1] as f32;
                        b += c[2] as f32;
                        a += 1.0;
                    }
                }
            }
            if a == 0.0 {
                px.extend_from_slice(&[0, 0, 0, 0]);
            } else {
                let n = (SS * SS) as f32;
                px.extend_from_slice(&[
                    (r / a).round() as u8,
                    (g / a).round() as u8,
                    (b / a).round() as u8,
                    (a / n * 255.0).round() as u8,
                ]);
            }
        }
    }
    px
}

/// Colour at unit coordinates (`u` right, `v` down), or `None` if transparent.
fn sample(u: f32, v: f32, fill: [u8; 3]) -> Option<[u8; 3]> {
    if !in_shield(u, v) {
        return None;
    }
    if in_padlock(u, v) {
        return Some([0xff, 0xff, 0xff]);
    }
    // A darker rim just inside the edge gives the shield definition on light
    // backgrounds.
    let rim = !in_shield(0.5 + (u - 0.5) / 0.88, 0.5 + (v - 0.52) / 0.88);
    Some(if rim { shade(fill, 0.72) } else { fill })
}

fn shade(c: [u8; 3], k: f32) -> [u8; 3] {
    c.map(|x| (x as f32 * k) as u8)
}

/// Shield: straight sides with rounded top corners, tapering to a point.
fn in_shield(u: f32, v: f32) -> bool {
    const HALF: f32 = 0.38;
    const TOP: f32 = 0.06;
    const WAIST: f32 = 0.50;
    const TIP: f32 = 0.96;
    let dx = (u - 0.5).abs();
    if !(TOP..=TIP).contains(&v) {
        return false;
    }
    if v < WAIST {
        // Rounded top corners of radius R.
        const R: f32 = 0.10;
        let (cx, cy) = (HALF - R, TOP + R);
        if dx > cx && v < cy {
            return (dx - cx).powi(2) + (v - cy).powi(2) <= R * R;
        }
        dx <= HALF
    } else {
        // Elliptical taper from the waist to the tip.
        let t = (v - WAIST) / (TIP - WAIST);
        dx <= HALF * (1.0 - t * t).sqrt()
    }
}

/// Padlock: a rounded body with a keyhole, and a shackle arch above it.
fn in_padlock(u: f32, v: f32) -> bool {
    let dx = (u - 0.5).abs();
    // Keyhole: a round head and a slot, cut out of the body.
    let keyhole = ((u - 0.5).powi(2) + (v - 0.60).powi(2)).sqrt() <= 0.045
        || (dx <= 0.018 && (0.60..=0.69).contains(&v));
    let body = rounded_rect(dx, v, 0.17, 0.45, 0.74, 0.035) && !keyhole;
    // Shackle: half ring centred above the body; the legs reach into it.
    let (cy, outer, inner) = (0.40, 0.125, 0.075);
    let d = ((u - 0.5).powi(2) + (v - cy).powi(2)).sqrt();
    let arch = v <= cy && d <= outer && d >= inner;
    let legs = (cy..=0.46).contains(&v) && dx >= inner && dx <= outer;
    body || arch || legs
}

/// Rect centred on u = 0.5 with half-width `hw`, spanning `top..=bottom`, with
/// corner radius `r`. `dx` is the distance from the centre line.
fn rounded_rect(dx: f32, v: f32, hw: f32, top: f32, bottom: f32, r: f32) -> bool {
    if dx > hw || v < top || v > bottom {
        return false;
    }
    let cx = hw - r;
    let cy = if v < top + r { top + r } else { bottom - r };
    if dx > cx && (v < top + r || v > bottom - r) {
        return (dx - cx).powi(2) + (v - cy).powi(2) <= r * r;
    }
    true
}

// Used by build.rs and the tests, not by the app itself.
#[cfg_attr(not(test), allow(dead_code))]
/// Encodes the icon at `sizes` as a Windows `.ico` with 32-bit BGRA DIB images.
pub fn ico(sizes: &[u32], fill: [u8; 3]) -> Vec<u8> {
    let images: Vec<Vec<u8>> = sizes.iter().map(|&s| dib(s, &render(s, fill))).collect();
    let mut out = Vec::new();
    out.extend_from_slice(&0u16.to_le_bytes()); // reserved
    out.extend_from_slice(&1u16.to_le_bytes()); // type: icon
    out.extend_from_slice(&(sizes.len() as u16).to_le_bytes());
    let mut offset = 6 + 16 * sizes.len() as u32;
    for (&s, img) in sizes.iter().zip(&images) {
        let dim = if s >= 256 { 0 } else { s as u8 }; // 0 means 256
        out.extend_from_slice(&[dim, dim, 0, 0]);
        out.extend_from_slice(&1u16.to_le_bytes()); // planes
        out.extend_from_slice(&32u16.to_le_bytes()); // bits per pixel
        out.extend_from_slice(&(img.len() as u32).to_le_bytes());
        out.extend_from_slice(&offset.to_le_bytes());
        offset += img.len() as u32;
    }
    for img in images {
        out.extend_from_slice(&img);
    }
    out
}

// Used by build.rs and the tests, not by the app itself.
#[cfg_attr(not(test), allow(dead_code))]
/// BITMAPINFOHEADER + bottom-up BGRA rows + an all-zero AND mask.
fn dib(size: u32, rgba: &[u8]) -> Vec<u8> {
    let mask_row = size.div_ceil(32) * 4;
    let mut out = Vec::new();
    out.extend_from_slice(&40u32.to_le_bytes());
    out.extend_from_slice(&(size as i32).to_le_bytes());
    out.extend_from_slice(&(2 * size as i32).to_le_bytes()); // XOR + AND
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&32u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // BI_RGB
    out.extend_from_slice(&(size * size * 4 + mask_row * size).to_le_bytes());
    out.extend_from_slice(&[0; 16]); // resolution and palette fields
    for y in (0..size).rev() {
        for x in 0..size {
            let i = ((y * size + x) * 4) as usize;
            out.extend_from_slice(&[rgba[i + 2], rgba[i + 1], rgba[i], rgba[i + 3]]);
        }
    }
    out.resize(out.len() + (mask_row * size) as usize, 0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alpha(px: &[u8], size: u32, x: u32, y: u32) -> u8 {
        px[((y * size + x) * 4 + 3) as usize]
    }

    #[test]
    fn shape_is_opaque_inside_and_clear_at_corners() {
        let px = render(64, APP);
        assert_eq!(px.len(), 64 * 64 * 4);
        assert_eq!(alpha(&px, 64, 0, 0), 0);
        assert_eq!(alpha(&px, 64, 63, 63), 0);
        assert_eq!(alpha(&px, 64, 32, 20), 255);
        // The padlock body is white.
        let i = ((40 * 64 + 22) * 4) as usize;
        assert_eq!(&px[i..i + 3], &[0xff, 0xff, 0xff]);
    }

    #[test]
    fn ico_directory_matches_images() {
        let data = ico(&ICO_SIZES, APP);
        assert_eq!(&data[..4], &[0, 0, 1, 0]);
        assert_eq!(
            u16::from_le_bytes([data[4], data[5]]) as usize,
            ICO_SIZES.len()
        );
        let mut end = 6 + 16 * ICO_SIZES.len();
        for (k, &s) in ICO_SIZES.iter().enumerate() {
            let e = &data[6 + 16 * k..6 + 16 * (k + 1)];
            assert_eq!(e[0], if s == 256 { 0 } else { s as u8 });
            let len = u32::from_le_bytes(e[8..12].try_into().unwrap()) as usize;
            let off = u32::from_le_bytes(e[12..16].try_into().unwrap()) as usize;
            assert_eq!(off, end);
            assert_eq!(
                u32::from_le_bytes(data[off..off + 4].try_into().unwrap()),
                40
            );
            end += len;
        }
        assert_eq!(end, data.len());
    }
}
