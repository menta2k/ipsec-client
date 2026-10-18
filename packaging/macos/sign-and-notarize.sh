#!/bin/sh
# Sign and notarize the macOS installer for a release (004 T046,
# contracts/macos-system-integration.md). Run after packaging/macos/build.sh
# on a macOS runner; it rebuilds the package from the signed binaries.
#
# Secrets (environment):
#   MACOS_APP_CERT_P12        base64 Developer ID Application certificate (.p12)
#   MACOS_INSTALLER_CERT_P12  base64 Developer ID Installer certificate (.p12)
#   MACOS_CERT_PASSWORD       password of both .p12 files
#   MACOS_NOTARY_KEY          base64 App Store Connect API key (.p8)
#   MACOS_NOTARY_KEY_ID       its key ID
#   MACOS_NOTARY_ISSUER       its issuer ID
#
# Without them it prints a notice and exits 0, so the release still ships
# the unsigned package.
set -eu

cd "$(dirname "$0")/../.."
out=target/macos
for v in MACOS_APP_CERT_P12 MACOS_INSTALLER_CERT_P12 MACOS_CERT_PASSWORD \
         MACOS_NOTARY_KEY MACOS_NOTARY_KEY_ID MACOS_NOTARY_ISSUER; do
    eval "val=\${$v:-}"
    if [ -z "$val" ]; then
        echo "NOTICE: $v is not set; the package stays UNSIGNED and not notarized."
        exit 0
    fi
done

version="$(sed -n '/^\[workspace\.package\]/,/^\[/s/^version *= *"\(.*\)"/\1/p' Cargo.toml)"
work="$(mktemp -d)"
keychain="$work/signing.keychain-db"
kc_pass="$(openssl rand -hex 24)"
cleanup() {
    security delete-keychain "$keychain" 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT

# ---- temporary keychain with both identities --------------------------------
security create-keychain -p "$kc_pass" "$keychain"
security set-keychain-settings -lut 3600 "$keychain"
security unlock-keychain -p "$kc_pass" "$keychain"
for c in APP INSTALLER; do
    eval "printf '%s' \"\$MACOS_${c}_CERT_P12\"" | base64 -d > "$work/$c.p12"
    security import "$work/$c.p12" -k "$keychain" -P "$MACOS_CERT_PASSWORD" \
        -T /usr/bin/codesign -T /usr/bin/productsign
done
security set-key-partition-list -S apple-tool:,apple: -s -k "$kc_pass" "$keychain" >/dev/null
security list-keychains -d user -s "$keychain" $(security list-keychains -d user | tr -d '"')
app_id="$(security find-identity -v -p codesigning "$keychain" | sed -n 's/.*"\(Developer ID Application: .*\)"/\1/p' | head -n 1)"
inst_id="$(security find-identity -v "$keychain" | sed -n 's/.*"\(Developer ID Installer: .*\)"/\1/p' | head -n 1)"
[ -n "$app_id" ] && [ -n "$inst_id" ] || { echo "error: Developer ID identities not found" >&2; exit 1; }

# ---- sign the binaries and the app (hardened runtime, no entitlements) ------
sign() { codesign --force --options runtime --timestamp --keychain "$keychain" --sign "$app_id" "$@"; }
sign "$out/service-root/Library/PrivilegedHelperTools/ipsec-service"
sign "$out/app-root/IPsec Client.app/Contents/MacOS/ipsec-gui"
sign "$out/app-root/IPsec Client.app"
codesign --verify --strict --verbose=2 "$out/app-root/IPsec Client.app"

# ---- rebuild the components and the product archive, then sign it -----------
pkgbuild --root "$out/app-root" --component-plist "$out/app-components.plist" \
    --install-location /Applications \
    --identifier net.ipsec-client.pkg.app --version "$version" "$out/app.pkg" >/dev/null
pkgbuild --root "$out/service-root" --scripts packaging/macos/scripts --install-location / \
    --identifier net.ipsec-client.pkg.service --version "$version" "$out/service.pkg" >/dev/null
unsigned="$work/unsigned.pkg"
productbuild --distribution "$out/distribution.xml" --package-path "$out" "$unsigned" >/dev/null
pkg="$out/IpsecClient-$version.pkg"
productsign --timestamp --keychain "$keychain" --sign "$inst_id" "$unsigned" "$pkg"

# ---- notarize and staple -------------------------------------------------------
printf '%s' "$MACOS_NOTARY_KEY" | base64 -d > "$work/notary.p8"
xcrun notarytool submit "$pkg" --wait \
    --key "$work/notary.p8" --key-id "$MACOS_NOTARY_KEY_ID" --issuer "$MACOS_NOTARY_ISSUER"
xcrun stapler staple "$pkg"
spctl --assess --type install --verbose=2 "$pkg"

# ---- the disk image holds the signed package -----------------------------------
rm -f "$out/dmg/Install IPsec Client.pkg" "$out/IpsecClient-$version.dmg"
cp "$pkg" "$out/dmg/Install IPsec Client.pkg"
hdiutil create -volname "IPsec Client $version" -srcfolder "$out/dmg" \
    -fs HFS+ -format UDZO -ov "$out/IpsecClient-$version.dmg" >/dev/null
codesign --timestamp --keychain "$keychain" --sign "$app_id" "$out/IpsecClient-$version.dmg"
echo "Signed and notarized $pkg"
