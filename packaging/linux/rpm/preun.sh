# ipsec-client: RPM %preun. $1 = 0 on removal, 1 on upgrade. Stopping the
# service tears down any tunnel and reverts routes/DNS.
if [ "$1" -eq 0 ] && [ -d /run/systemd/system ]; then
    systemctl disable --now ipsec-client.service || :
fi
