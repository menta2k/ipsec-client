#!/bin/sh
# Build the Linux packages (002 T029):
#   target/debian/ipsec-client_<version>_amd64.deb
#   target/generate-rpm/ipsec-client-<version>-1.x86_64.rpm
#
# Needs: Rust, the GUI build dependencies (libgtk-3-dev, libxdo-dev,
# libayatana-appindicator3-dev, pkg-config), and the packaging tools:
#   cargo install cargo-deb cargo-generate-rpm
# Pass --deb-only or --rpm-only to build one format.
set -eu

cd "$(dirname "$0")/../.."

want_deb=1
want_rpm=1
case "${1:-}" in
    --deb-only) want_rpm=0 ;;
    --rpm-only) want_deb=0 ;;
    "") ;;
    *) echo "usage: $0 [--deb-only | --rpm-only]" >&2; exit 2 ;;
esac

need() {
    if ! command -v "$1" >/dev/null 2>&1 && ! cargo "$2" --version >/dev/null 2>&1; then
        echo "error: $2 is not installed (cargo install $1)" >&2
        exit 1
    fi
}
[ "$want_deb" -eq 1 ] && need cargo-deb deb
[ "$want_rpm" -eq 1 ] && need cargo-generate-rpm generate-rpm

echo "==> building release binaries"
cargo build --release --locked -p ipsec-service -p ipsec-gui

echo "==> rendering icons"
rm -rf target/linux-icons
target/release/ipsec-gui --write-icons target/linux-icons >/dev/null

if [ "$want_deb" -eq 1 ]; then
    echo "==> building .deb"
    cargo deb -p ipsec-gui --no-build
fi
if [ "$want_rpm" -eq 1 ]; then
    echo "==> building .rpm"
    cargo generate-rpm -p crates/ipsec-gui
fi

echo "==> done"
ls -1 target/debian/*.deb target/generate-rpm/*.rpm 2>/dev/null || true
