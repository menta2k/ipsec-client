#!/bin/sh
# Build the macOS disk image:
#   target/macos/IpsecClient-<version>.dmg
#
# The image holds "IPsec Client.app" with universal (Apple Silicon + Intel)
# binaries of the GUI and the service. The macOS service back-end is not
# written yet (feature 004), so for now the app can only drive the simulated
# service (`ipsec-service run --mock`). The image is unsigned.
#
# Needs: macOS with the Xcode command-line tools, and Rust with the targets
#   rustup target add aarch64-apple-darwin x86_64-apple-darwin
set -eu

cd "$(dirname "$0")/../.."

version="$(sed -n '/^\[workspace\.package\]/,/^\[/s/^version *= *"\(.*\)"/\1/p' Cargo.toml)"
[ -n "$version" ] || { echo "error: workspace version not found" >&2; exit 1; }

export MACOSX_DEPLOYMENT_TARGET=13.0
for t in aarch64-apple-darwin x86_64-apple-darwin; do
    cargo build --release --locked --target "$t" -p ipsec-gui -p ipsec-service
done

out=target/macos
app="$out/IPsec Client.app"
rm -rf "$out"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"

for bin in ipsec-gui ipsec-service; do
    lipo -create -output "$app/Contents/MacOS/$bin" \
        "target/aarch64-apple-darwin/release/$bin" \
        "target/x86_64-apple-darwin/release/$bin"
done

# App icon, rendered by the GUI itself (no image file is checked in).
icons="$out/icons"
"$app/Contents/MacOS/ipsec-gui" --write-icons "$icons" >/dev/null
src="$icons/hicolor/256x256/apps/ipsec-client.png"
iconset="$out/AppIcon.iconset"
mkdir -p "$iconset"
for s in 16 32 128 256; do
    sips -z "$s" "$s" "$src" --out "$iconset/icon_${s}x${s}.png" >/dev/null
    d=$((s * 2))
    sips -z "$d" "$d" "$src" --out "$iconset/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$iconset" -o "$app/Contents/Resources/AppIcon.icns"

cat > "$app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>IPsec Client</string>
    <key>CFBundleDisplayName</key><string>IPsec Client</string>
    <key>CFBundleIdentifier</key><string>net.ipsec-client.gui</string>
    <key>CFBundleExecutable</key><string>ipsec-gui</string>
    <key>CFBundleIconFile</key><string>AppIcon</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleVersion</key><string>$version</string>
    <key>CFBundleShortVersionString</key><string>$version</string>
    <key>LSMinimumSystemVersion</key><string>13.0</string>
    <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
EOF

# Disk image: the app plus an Applications shortcut for drag-to-install.
stage="$out/dmg"
mkdir -p "$stage"
cp -R "$app" "$stage/"
ln -s /Applications "$stage/Applications"
dmg="$out/IpsecClient-$version.dmg"
hdiutil create -volname "IPsec Client $version" -srcfolder "$stage" \
    -fs HFS+ -format UDZO -ov "$dmg" >/dev/null
echo "Built $dmg (UNSIGNED)"
