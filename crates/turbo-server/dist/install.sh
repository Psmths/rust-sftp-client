#!/bin/sh
# Installs rsftp-turbo as a systemd service. Run as root from the extracted archive.
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "Please run as root (e.g. sudo ./install.sh)" >&2
    exit 1
fi
here=$(cd "$(dirname "$0")" && pwd)

install -m 0755 "$here/rsftp-turbo" /usr/local/bin/rsftp-turbo
install -m 0644 "$here/rsftp-turbo.service" /etc/systemd/system/rsftp-turbo.service
systemctl daemon-reload
systemctl enable rsftp-turbo.service
# restart (not just start) so an update replaces a running old version
systemctl restart rsftp-turbo.service

echo
echo "rsftp-turbo is installed and running:"
systemctl --no-pager --lines=0 status rsftp-turbo.service || true
echo
echo "Allow UDP port 6767 through the firewall, for example:"
echo "  firewall-cmd --permanent --add-port=6767/udp && firewall-cmd --reload"
echo "  ufw allow 6767/udp"
echo
echo "Make sure /usr/local/bin is on the PATH of SSH sessions (it is by default),"
echo "because the client runs 'rsftp-turbo ticket' over SSH."
