#!/bin/sh
# Build the macOS installer (004 T043):
#   target/macos/IpsecClient-<version>.pkg   product archive: app + service
#   target/macos/IpsecClient-<version>.dmg   disk image holding the .pkg
#
# Universal (Apple Silicon + Intel) binaries, macOS 13 or later. The output
# is unsigned; packaging/macos/sign-and-notarize.sh signs a release.
#
# Needs: macOS with the Xcode command-line tools, and Rust with the targets
#   rustup target add aarch64-apple-darwin x86_64-apple-darwin
set -eu

cd "$(dirname "$0")/../.."
here=packaging/macos

version="$(sed -n '/^\[workspace\.package\]/,/^\[/s/^version *= *"\(.*\)"/\1/p' Cargo.toml)"
[ -n "$version" ] || { echo "error: workspace version not found" >&2; exit 1; }

export MACOSX_DEPLOYMENT_TARGET=13.0
for t in aarch64-apple-darwin x86_64-apple-darwin; do
    cargo build --release --locked --target "$t" -p ipsec-gui -p ipsec-service
done

out=target/macos
rm -rf "$out"
mkdir -p "$out"
universal() { # <binary> <destination>
    lipo -create -output "$2" \
        "target/aarch64-apple-darwin/release/$1" \
        "target/x86_64-apple-darwin/release/$1"
}

# ---- app component: /Applications/IPsec Client.app ------------------------
app_root="$out/app-root"
app="$app_root/IPsec Client.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
universal ipsec-gui "$app/Contents/MacOS/ipsec-gui"
sed "s/@VERSION@/$version/g" "$here/Info.plist" > "$app/Contents/Info.plist"
plutil -lint "$app/Contents/Info.plist" >/dev/null
# The icon is rendered by the GUI itself; no image file is checked in.
"$app/Contents/MacOS/ipsec-gui" --write-icons "$out/icons" >/dev/null
iconutil -c icns "$out/icons/AppIcon.iconset" -o "$app/Contents/Resources/AppIcon.icns"

# Not relocatable: always /Applications, never a copy found elsewhere.
pkgbuild --analyze --root "$app_root" "$out/app-components.plist" >/dev/null
plutil -replace 0.BundleIsRelocatable -bool false "$out/app-components.plist"
pkgbuild --root "$app_root" --component-plist "$out/app-components.plist" \
    --install-location /Applications \
    --identifier net.ipsec-client.pkg.app --version "$version" \
    "$out/app.pkg" >/dev/null

# ---- service component: daemon binary, plist and scripts ------------------
svc_root="$out/service-root"
mkdir -p "$svc_root/Library/PrivilegedHelperTools" "$svc_root/Library/LaunchDaemons"
universal ipsec-service "$svc_root/Library/PrivilegedHelperTools/ipsec-service"
install -m 0644 "$here/net.ipsec-client.service.plist" "$svc_root/Library/LaunchDaemons/"
plutil -lint "$svc_root/Library/LaunchDaemons/net.ipsec-client.service.plist" >/dev/null
chmod 0755 "$here/scripts/preinstall" "$here/scripts/postinstall"
pkgbuild --root "$svc_root" --scripts "$here/scripts" --install-location / \
    --identifier net.ipsec-client.pkg.service --version "$version" \
    "$out/service.pkg" >/dev/null

# ---- product archive and disk image ---------------------------------------
sed "s/@VERSION@/$version/g" "$here/distribution.xml" > "$out/distribution.xml"
pkg="$out/IpsecClient-$version.pkg"
productbuild --distribution "$out/distribution.xml" --package-path "$out" "$pkg" >/dev/null

stage="$out/dmg"
mkdir -p "$stage"
cp "$pkg" "$stage/Install IPsec Client.pkg"
dmg="$out/IpsecClient-$version.dmg"
hdiutil create -volname "IPsec Client $version" -srcfolder "$stage" \
    -fs HFS+ -format UDZO -ov "$dmg" >/dev/null

echo "Built $pkg (UNSIGNED)"
echo "Built $dmg (UNSIGNED)"
