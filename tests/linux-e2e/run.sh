#!/usr/bin/env bash
# End-to-end test of the Linux client against a real strongSwan gateway, in
# two network namespaces (002 T037, research R11). Run as root:
#
#   sudo tests/linux-e2e/run.sh
#
#   vpn-cli: veth-cli 10.99.0.2/24   <-->   vpn-gw: veth-gw 10.99.0.1/24
#            ipsec-service run                       charon + dummy0 10.99.1.1/24
#
# Needs: iproute2, iputils-ping, strongswan-swanctl, charon-systemd,
# libcharon-extra-plugins, libstrongswan-extra-plugins,
# libstrongswan-standard-plugins (openssl: AES-GCM) and
# libcharon-extauth-plugins (eap-mschapv2).
#
# Binaries: set SERVICE_BIN and DRIVER_BIN to prebuilt ones (CI does), or
# leave them unset to build with cargo as the user who invoked sudo.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root (sudo $0)" >&2
    exit 2
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d /tmp/ipsec-e2e.XXXXXX)"
chmod 755 "$WORK"
SVC_PID=""
CHARON_PID=""

dump_logs() {
    echo "----- ipsec-service log -----"
    cat "$WORK/service.log" 2>/dev/null || true
    echo "----- charon log -----"
    journalctl --no-pager -o cat -t charon-systemd --since "-10min" 2>/dev/null | tail -n 200 || true
}

cleanup() {
    status=$?
    set +e
    if [ "$status" -ne 0 ]; then
        dump_logs
    fi
    [ -n "$SVC_PID" ] && kill "$SVC_PID" 2>/dev/null && wait "$SVC_PID" 2>/dev/null
    [ -n "$CHARON_PID" ] && kill "$CHARON_PID" 2>/dev/null && wait "$CHARON_PID" 2>/dev/null
    ip netns del vpn-cli 2>/dev/null
    ip netns del vpn-gw 2>/dev/null
    rm -rf "$WORK"
    exit "$status"
}
trap cleanup EXIT

# ---- binaries ------------------------------------------------------------
as_user() {
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
        runuser -u "$SUDO_USER" -- "$@"
    else
        "$@"
    fi
}
if [ -z "${SERVICE_BIN:-}" ] || [ -z "${DRIVER_BIN:-}" ]; then
    echo "==> building the service and the e2e driver"
    (cd "$ROOT" && as_user cargo build -p ipsec-service)
    SERVICE_BIN="$ROOT/target/debug/ipsec-service"
    DRIVER_BIN="$(cd "$ROOT" && as_user cargo test -p ipsec-service --test linux_e2e --no-run --message-format=json \
        | sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' | grep /linux_e2e- | tail -n 1)"
fi
[ -x "$SERVICE_BIN" ] || { echo "no service binary: $SERVICE_BIN" >&2; exit 1; }
[ -x "$DRIVER_BIN" ] || { echo "no driver binary: $DRIVER_BIN" >&2; exit 1; }

# ---- namespaces ----------------------------------------------------------
echo "==> creating namespaces"
ip netns del vpn-cli 2>/dev/null || true
ip netns del vpn-gw 2>/dev/null || true
ip netns add vpn-cli
ip netns add vpn-gw
ip link add veth-cli type veth peer name veth-gw
ip link set veth-cli netns vpn-cli
ip link set veth-gw netns vpn-gw
ip -n vpn-cli link set lo up
ip -n vpn-cli addr add 10.99.0.2/24 dev veth-cli
ip -n vpn-cli link set veth-cli up
ip -n vpn-gw link set lo up
ip -n vpn-gw addr add 10.99.0.1/24 dev veth-gw
ip -n vpn-gw link set veth-gw up
ip -n vpn-gw link add dummy0 type dummy
ip -n vpn-gw addr add 10.99.1.1/24 dev dummy0
ip -n vpn-gw link set dummy0 up
# Replies to the client's pool need a route; the XFRM policy then encrypts.
ip -n vpn-gw route add 10.99.2.0/24 via 10.99.0.2 dev veth-gw

# ---- gateway ---------------------------------------------------------------
echo "==> starting strongSwan in vpn-gw"
# A charon started by the package in the host namespace would own the vici
# socket that swanctl talks to.
systemctl stop strongswan.service 2>/dev/null || true
ip netns exec vpn-gw /usr/sbin/charon-systemd &
CHARON_PID=$!
for _ in $(seq 1 50); do
    ip netns exec vpn-gw swanctl --stats >/dev/null 2>&1 && break
    sleep 0.2
done
ip netns exec vpn-gw swanctl --load-all --file "$ROOT/tests/linux-e2e/swanctl.conf"

# ---- client ------------------------------------------------------------------
echo "==> starting ipsec-service in vpn-cli"
printf 'nameserver 10.99.0.1\n' > "$WORK/resolv.conf"
export IPSEC_CLIENT_STATE_DIR="$WORK/state"
export IPSEC_CLIENT_SOCKET="$WORK/ipsec-client.sock"
export IPSEC_CLIENT_RESOLV_CONF="$WORK/resolv.conf"
export E2E_RESOLV_CONF="$WORK/resolv.conf"
export IPSEC_LOG="${IPSEC_LOG:-debug}"
ip netns exec vpn-cli "$SERVICE_BIN" run > "$WORK/service.log" 2>&1 &
SVC_PID=$!
for _ in $(seq 1 50); do
    [ -S "$IPSEC_CLIENT_SOCKET" ] && break
    if ! kill -0 "$SVC_PID" 2>/dev/null; then
        echo "ipsec-service exited during start-up" >&2
        exit 1
    fi
    sleep 0.2
done
[ -S "$IPSEC_CLIENT_SOCKET" ] || { echo "service socket did not appear" >&2; exit 1; }

# ---- test ------------------------------------------------------------------
echo "==> running the e2e driver"
ip netns exec vpn-cli "$DRIVER_BIN" --ignored --test-threads=1 --nocapture
echo "==> e2e passed"
