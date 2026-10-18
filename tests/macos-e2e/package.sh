#!/bin/sh
# Installer check on a macOS runner (004 T045): install, upgrade, uninstall
# (profiles kept), reinstall, uninstall --remove-data. Needs sudo and the
# package from packaging/macos/build.sh.
set -eu

cd "$(dirname "$0")/../.."
pkg="$(ls target/macos/IpsecClient-*.pkg | head -n 1)"
label=system/net.ipsec-client.service
data="/Library/Application Support/IpsecClient"
logs=/Library/Logs/IpsecClient
sock=/var/run/ipsec-client/ipsec-client.sock
secret="pkg-check-secret-$$-$(date +%s)"

fail() { echo "FAIL: $*" >&2; sudo cat "$logs/service.out" 2>/dev/null | tail -n 50 >&2 || true; exit 1; }
step() { echo "==> $*"; }
install_pkg() { sudo installer -pkg "$pkg" -target / >/dev/null || fail "installer"; }
wait_for() { # <description> <command...>
    what="$1"; shift
    i=0
    until "$@" >/dev/null 2>&1; do
        i=$((i + 1))
        [ "$i" -le 40 ] || fail "timed out waiting for $what"
        sleep 0.5
    done
}
running() { sudo launchctl print "$label" | grep -q 'state = running'; }
has_profile() { sudo grep -q '"name": "Package Check"' "$data/profiles.json"; }

step "install"
install_pkg
wait_for "the daemon" running
wait_for "the socket" test -S "$sock"
for f in /Library/PrivilegedHelperTools/ipsec-service "/Applications/IPsec Client.app/Contents/MacOS/ipsec-gui"; do
    archs="$(lipo -archs "$f")"
    case "$archs" in *arm64*x86_64*|*x86_64*arm64*) ;; *) fail "$f is not universal: $archs" ;; esac
done
[ "$(readlink /usr/local/bin/ipsec-service)" = /Library/PrivilegedHelperTools/ipsec-service ] \
    || fail "command-line symlink"
[ "$(stat -f '%Su:%Sg %Lp' "$(dirname "$sock")")" = "root:admin 750" ] || fail "socket directory: $(stat -f '%Su:%Sg %Lp' "$(dirname "$sock")")"
[ "$(sudo stat -f '%Su:%Sg %Lp' "$data")" = "root:wheel 700" ] || fail "data directory"
pkgutil --pkgs | grep -q '^net.ipsec-client.pkg.service$' || fail "service receipt"

step "profile import (administrator)"
cat > "$TMPDIR/profile.json" <<JSON
{ "profiles": [ { "name": "Package Check", "gateway": "192.0.2.1", "local_id": "pkg-check",
                  "auth": "psk", "psk": "$secret" } ] }
JSON
sudo /usr/local/bin/ipsec-service profile import "$TMPDIR/profile.json" || fail "profile import"
rm -f "$TMPDIR/profile.json"
has_profile || fail "profile not stored"
# The PSK must never be on disk in the clear (SC-006).
if sudo grep -rqF "$secret" "$data" "$logs"; then fail "the PSK is stored in plain text"; fi

step "access group shown to a non-root user"
/usr/local/bin/ipsec-service access-group | grep -q 'gid 80' || fail "access-group without sudo"

step "upgrade keeps profiles"
install_pkg
wait_for "the daemon after upgrade" running
has_profile || fail "profile lost on upgrade"

step "uninstall keeps profiles"
sudo /usr/local/bin/ipsec-service uninstall || fail "uninstall"
if sudo launchctl print "$label" >/dev/null 2>&1; then fail "daemon still loaded"; fi
for f in /Library/PrivilegedHelperTools/ipsec-service /Library/LaunchDaemons/net.ipsec-client.service.plist \
         /usr/local/bin/ipsec-service "/Applications/IPsec Client.app"; do
    [ ! -e "$f" ] || fail "$f left behind"
done
if pkgutil --pkgs | grep -q '^net.ipsec-client'; then fail "receipts left behind"; fi
has_profile || fail "uninstall deleted the profiles"

step "reinstall, then uninstall --remove-data"
install_pkg
wait_for "the daemon after reinstall" running
has_profile || fail "profile not picked up again"
sudo /usr/local/bin/ipsec-service uninstall --remove-data || fail "uninstall --remove-data"
[ ! -e "$data" ] || fail "data directory left behind"
[ ! -e "$logs" ] || fail "log directory left behind"

echo "==> package check passed"
