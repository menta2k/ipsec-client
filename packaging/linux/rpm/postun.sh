# ipsec-client: RPM %postun. RPM has no "purge": profiles in
# /var/lib/ipsec-client are always kept (remove them by hand if wanted).
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || :
fi
