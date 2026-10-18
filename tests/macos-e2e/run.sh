#!/bin/sh
# End-to-end test of the macOS service against the vpn-core mock gateway
# (004 T021). Run as root:
#
#   sudo tests/macos-e2e/run.sh
#
#   lo0 alias 10.99.0.1: mock_gateway (UDP 500/4500)
#   ipsec-service run, with its state and socket in a temporary directory
#
# Binaries: set SERVICE_BIN, DRIVER_BIN and GATEWAY_BIN to prebuilt ones (CI
# does), or leave them unset to build with cargo as the user who ran sudo.
set -eu

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo $0)" >&2; exit 2; }

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d /tmp/ipsec-e2e.XXXXXX)"
GW_PID=""
SVC_PID=""

cleanup() {
    status=$?
    set +e
    [ -n "$SVC_PID" ] && kill "$SVC_PID" 2>/dev/null && wait "$SVC_PID" 2>/dev/null
    [ -n "$GW_PID" ] && kill "$GW_PID" 2>/dev/null && wait "$GW_PID" 2>/dev/null
    if [ "$status" -ne 0 ]; then
        echo "----- ipsec-service log -----"
        cat "$WORK/service.log" 2>/dev/null
        echo "----- mock gateway -----"
        cat "$WORK/gateway.log" 2>/dev/null
    fi
    ifconfig lo0 -alias 10.99.0.1 2>/dev/null
    rm -rf "$WORK"
    exit "$status"
}
trap cleanup EXIT

as_user() {
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
        sudo -u "$SUDO_USER" "$@"
    else
        "$@"
    fi
}
if [ -z "${SERVICE_BIN:-}" ] || [ -z "${DRIVER_BIN:-}" ] || [ -z "${GATEWAY_BIN:-}" ]; then
    echo "==> building"
    (cd "$ROOT" && as_user cargo build -p ipsec-service -p vpn-core --example mock_gateway)
    SERVICE_BIN="$ROOT/target/debug/ipsec-service"
    GATEWAY_BIN="$ROOT/target/debug/examples/mock_gateway"
    DRIVER_BIN="$(cd "$ROOT" && as_user cargo test -p ipsec-service --test macos_e2e --no-run --message-format=json \
        | sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' | grep /macos_e2e- | tail -n 1)"
fi
for b in "$SERVICE_BIN" "$DRIVER_BIN" "$GATEWAY_BIN"; do
    [ -x "$b" ] || { echo "missing binary: $b" >&2; exit 1; }
done

echo "==> mock gateway on lo0 alias 10.99.0.1"
ifconfig lo0 alias 10.99.0.1/32
"$GATEWAY_BIN" 10.99.0.1 > "$WORK/gateway.log" 2>&1 &
GW_PID=$!
i=0
until grep -q '^ready' "$WORK/gateway.log"; do
    i=$((i + 1))
    [ "$i" -le 50 ] || { echo "mock gateway did not start" >&2; exit 1; }
    kill -0 "$GW_PID" 2>/dev/null || { echo "mock gateway exited" >&2; exit 1; }
    sleep 0.2
done

echo "==> ipsec-service run"
export IPSEC_CLIENT_STATE_DIR="$WORK/state"
export IPSEC_CLIENT_SOCKET="$WORK/run/ipsec-client.sock"
export IPSEC_LOG="${IPSEC_LOG:-debug}"
"$SERVICE_BIN" run > "$WORK/service.log" 2>&1 &
SVC_PID=$!
i=0
until [ -S "$IPSEC_CLIENT_SOCKET" ]; do
    i=$((i + 1))
    [ "$i" -le 50 ] || { echo "service socket did not appear" >&2; exit 1; }
    kill -0 "$SVC_PID" 2>/dev/null || { echo "ipsec-service exited during start-up" >&2; exit 1; }
    sleep 0.2
done

echo "==> running the e2e driver"
"$DRIVER_BIN" --ignored --test-threads=1 --nocapture
grep -q 'delete=true' "$WORK/gateway.log" || { echo "the gateway never saw an IKE DELETE" >&2; exit 1; }

echo "==> no secret in plain text (SC-006)"
# The state directory (profiles are encrypted), the service's own output at
# debug level, its log files, and the unified log.
unified="$(log show --last 15m --style compact --predicate 'process == "ipsec-service"' 2>/dev/null || true)"
for secret in "gateway-psk" "correct horse" "wrong password"; do
    if grep -rqF "$secret" "$WORK/state" "$WORK/service.log"; then
        echo "found '$secret' in plain text:" >&2
        grep -rlF "$secret" "$WORK/state" "$WORK/service.log" >&2
        exit 1
    fi
    if printf '%s' "$unified" | grep -qF "$secret"; then
        echo "found '$secret' in the unified log" >&2
        exit 1
    fi
done
echo "==> e2e passed"
