# ipsec-client: RPM %post. $1 = 1 on install, 2 on upgrade.
systemd-sysusers ipsec-client.conf || :
if [ "$1" -eq 1 ]; then
    user="${SUDO_USER:-}"
    if [ -z "$user" ] && [ -n "${PKEXEC_UID:-}" ]; then
        user="$(getent passwd "$PKEXEC_UID" | cut -d: -f1)"
    fi
    if [ -n "$user" ] && [ "$user" != "root" ] && id "$user" >/dev/null 2>&1; then
        usermod -a -G ipsec-client "$user" || :
        echo "ipsec-client: added $user to the ipsec-client group (log out and in to use the VPN)."
    fi
fi
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || :
    if [ "$1" -eq 1 ]; then
        systemctl enable --now ipsec-client.service || :
    else
        systemctl try-restart ipsec-client.service || :
    fi
fi
