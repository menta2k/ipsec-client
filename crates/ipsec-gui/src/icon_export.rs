//! `ipsec-gui --write-icons <dir>`: the PNG icon theme files Linux packages
//! install under `/usr/share/icons` (002 research R9), and the macOS
//! `AppIcon.iconset` that `iconutil` turns into the app icon (004 T042).
//! Rendered from `icon.rs`, so no image file is checked in.

use std::io;
use std::path::{Path, PathBuf};

/// The `.iconset` entries `iconutil` expects: 16 to 512 points at 1x and 2x.
pub fn iconset_files() -> Vec<(PathBuf, u32)> {
    [16u32, 32, 128, 256, 512]
        .iter()
        .flat_map(|&s| {
            [
                (format!("icon_{s}x{s}.png"), s),
                (format!("icon_{s}x{s}@2x.png"), s * 2),
            ]
        })
        .map(|(name, px)| (Path::new("AppIcon.iconset").join(name), px))
        .collect()
}

/// Write `hicolor/<n>x<n>/apps/ipsec-client.png` for every size, and
/// `AppIcon.iconset/`, into `dir`.
pub fn write_icons(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut written = Vec::new();
    let theme = crate::icon::icon_files(&crate::icon::PNG_SIZES);
    for (rel, size) in theme.into_iter().chain(iconset_files()) {
        let path = dir.join(rel);
        write_png(&path, size)?;
        written.push(path);
    }
    Ok(written)
}

fn write_png(path: &Path, size: u32) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = io::BufWriter::new(std::fs::File::create(path)?);
    let mut enc = png::Encoder::new(file, size, size);
    enc.set_color(png::ColorType::Rgba);
    enc.set_depth(png::BitDepth::Eight);
    let mut w = enc.write_header().map_err(io::Error::other)?;
    w.write_image_data(&crate::icon::render(size, crate::icon::APP))
        .map_err(io::Error::other)?;
    w.finish().map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_decodable_pngs_of_each_size() {
        let dir = std::env::temp_dir().join(format!("ipsec-icons-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let written = write_icons(&dir).unwrap();
        assert_eq!(written.len(), crate::icon::PNG_SIZES.len() + 10);
        let theme = crate::icon::icon_files(&crate::icon::PNG_SIZES);
        for (rel, size) in theme.into_iter().chain(iconset_files()) {
            let path = dir.join(&rel);
            let decoder =
                png::Decoder::new(io::BufReader::new(std::fs::File::open(&path).unwrap()));
            let reader = decoder.read_info().unwrap();
            let info = reader.info();
            assert_eq!(
                (info.width, info.height),
                (size, size),
                "{}",
                path.display()
            );
            assert_eq!(info.color_type, png::ColorType::Rgba);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn iconset_has_the_names_iconutil_expects() {
        let names: Vec<(String, u32)> = iconset_files()
            .into_iter()
            .map(|(p, px)| (p.to_string_lossy().replace('\\', "/"), px))
            .collect();
        assert_eq!(names.len(), 10);
        assert_eq!(names[0], ("AppIcon.iconset/icon_16x16.png".into(), 16));
        assert_eq!(names[1], ("AppIcon.iconset/icon_16x16@2x.png".into(), 32));
        assert_eq!(
            names[9],
            ("AppIcon.iconset/icon_512x512@2x.png".into(), 1024)
        );
    }
}
