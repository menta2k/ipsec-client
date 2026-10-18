#!/bin/sh
# The service under launchd (004 T028, T029). Run as root on a disposable
# Mac (CI): it installs the debug binary as the system daemon.
#
#   sudo SERVICE_BIN=... DRIVER_BIN=... GATEWAY_BIN=... tests/macos-e2e/daemon.sh
#
# 1. install; the daemon runs and serves the system socket
# 2. connect against the mock gateway, then `launchctl kill KILL`: launchd
#    restarts it within 10 s and the restart replays the journal, so no VPN
#    route or DNS is left
# 3. `stop` stops it and it stays stopped
# 4. connected again, `bootout` (SIGTERM): the gateway gets an IKE DELETE and
#    the network is restored before the process exits
# 5. uninstall --remove-data
set -eu

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo $0)" >&2; exit 2; }
for b in "${SERVICE_BIN:?}" "${DRIVER_BIN:?}" "${GATEWAY_BIN:?}"; do
    [ -x "$b" ] || { echo "missing binary: $b" >&2; exit 1; }
done

label=system/net.ipsec-client.service
WORK="$(mktemp -d /tmp/ipsec-daemon.XXXXXX)"
GW_PID=""
export IPSEC_CLIENT_SOCKET=/var/run/ipsec-client/ipsec-client.sock

cleanup() {
    status=$?
    set +e
    if [ "$status" -ne 0 ]; then
        echo "----- service.out -----"; tail -n 60 /Library/Logs/IpsecClient/service.out
        echo "----- mock gateway -----"; cat "$WORK/gateway.log"
    fi
    /usr/local/bin/ipsec-service uninstall --remove-data >/dev/null 2>&1 \
        || "$SERVICE_BIN" uninstall --remove-data >/dev/null 2>&1
    [ -n "$GW_PID" ] && kill "$GW_PID" 2>/dev/null && wait "$GW_PID" 2>/dev/null
    ifconfig lo0 -alias 10.99.0.1 2>/dev/null
    rm -rf "$WORK"
    exit "$status"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pid() { launchctl print "$label" 2>/dev/null | sed -n 's/^[[:space:]]*pid = \([0-9]*\)$/\1/p'; }
vpn_dns() { scutil --dns | grep -q 10.10.0.1; }
vpn_utun() { ifconfig | grep -q 'inet 10.10.0.2 '; }
vpn_route() { route -n get 10.10.0.9 2>/dev/null | grep -q 'interface: utun'; }
wait_for() { # <seconds> <description> <command...>
    limit=$(($1 * 5)); what="$2"; shift 2
    i=0
    until "$@"; do
        i=$((i + 1))
        [ "$i" -le "$limit" ] || fail "timed out waiting for $what"
        sleep 0.2
    done
}
clean() { ! vpn_dns && ! vpn_utun && ! vpn_route; }
running() { [ -n "$(pid)" ]; }
stopped() { [ -z "$(pid)" ]; }
connect() { "$DRIVER_BIN" --ignored --exact daemon_connect_and_stay --test-threads=1 >/dev/null || fail "connect"; }

echo "==> mock gateway"
ifconfig lo0 alias 10.99.0.1/32
"$GATEWAY_BIN" 10.99.0.1 > "$WORK/gateway.log" 2>&1 &
GW_PID=$!
wait_for 10 "the gateway" grep -q '^ready' "$WORK/gateway.log"

echo "==> install"
install -d -o root -g wheel -m 0755 /Library/PrivilegedHelperTools
install -o root -g wheel -m 0755 "$SERVICE_BIN" /Library/PrivilegedHelperTools/ipsec-service
/Library/PrivilegedHelperTools/ipsec-service install || fail "install"
wait_for 10 "the daemon" running
wait_for 10 "the socket" test -S "$IPSEC_CLIENT_SOCKET"

echo "==> crash while connected"
connect
vpn_dns && vpn_utun && vpn_route || fail "tunnel not configured"
first="$(pid)"
launchctl kill KILL "$label"
restarted() { p="$(pid)"; [ -n "$p" ] && [ "$p" != "$first" ]; }
wait_for 10 "a restart" restarted
wait_for 10 "journal replay after the crash" clean

echo "==> stop stays stopped"
/Library/PrivilegedHelperTools/ipsec-service stop || fail "stop"
wait_for 10 "the daemon to stop" stopped
sleep 6
[ -z "$(pid)" ] || fail "launchd restarted a cleanly stopped daemon"

echo "==> clean shutdown sends an IKE DELETE"
/Library/PrivilegedHelperTools/ipsec-service start || fail "start"
wait_for 10 "the daemon" running
wait_for 10 "the socket" test -S "$IPSEC_CLIENT_SOCKET"
# Nothing so far sent a DELETE: the crash could not, and nothing was
# connected when the daemon was stopped.
if grep -q 'delete=true' "$WORK/gateway.log"; then fail "unexpected IKE DELETE before the shutdown"; fi
connect
launchctl bootout "$label" || fail "bootout"
wait_for 10 "the IKE DELETE" grep -q 'delete=true' "$WORK/gateway.log"
clean || fail "network not restored by the SIGTERM shutdown"

echo "==> daemon lifecycle passed"
