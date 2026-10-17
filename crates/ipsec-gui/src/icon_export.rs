//! `ipsec-gui --write-icons <dir>`: the PNG icon theme files Linux packages
//! install under `/usr/share/icons` (002 research R9), rendered from
//! `icon.rs` so no image file is checked in.

use std::io;
use std::path::Path;

/// Write `hicolor/<n>x<n>/apps/ipsec-client.png` for every size into `dir`.
pub fn write_icons(dir: &Path) -> io::Result<Vec<std::path::PathBuf>> {
    let mut written = Vec::new();
    for (rel, size) in crate::icon::icon_files(&crate::icon::PNG_SIZES) {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = io::BufWriter::new(std::fs::File::create(&path)?);
        let mut enc = png::Encoder::new(file, size, size);
        enc.set_color(png::ColorType::Rgba);
        enc.set_depth(png::BitDepth::Eight);
        let mut w = enc.write_header().map_err(io::Error::other)?;
        w.write_image_data(&crate::icon::render(size, crate::icon::APP))
            .map_err(io::Error::other)?;
        w.finish().map_err(io::Error::other)?;
        written.push(path);
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_decodable_pngs_of_each_size() {
        let dir = std::env::temp_dir().join(format!("ipsec-icons-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let written = write_icons(&dir).unwrap();
        assert_eq!(written.len(), crate::icon::PNG_SIZES.len());
        for (rel, size) in crate::icon::icon_files(&crate::icon::PNG_SIZES) {
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
}
