#!/usr/bin/env bash
# Installs the acme-hub systemd unit and config directory on this host.
# Run as root, after building acme-hub and copying it to /usr/local/bin.
set -euo pipefail

BINARY=/usr/local/bin/acme-hub
CONFIG_DIR=/etc/acme-hub
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
	echo "run as root" >&2
	exit 1
fi

if [ ! -x "$BINARY" ]; then
	echo "expected $BINARY to exist and be executable - copy the built acme-hub binary there first" >&2
	exit 1
fi

# config.yaml holds no secrets (only \${VAR} placeholders, expanded from
# acme-hub.env), so a plain root-owned 0755 directory is fine - no special
# DynamicUser-aware ownership needed here, unlike the data directory
# (which systemd's StateDirectory= in the unit handles automatically).
install -d -m 0755 "$CONFIG_DIR"

# A stable group (unlike DynamicUser's freshly-allocated, per-start UID)
# that acme-hub.service grants the hub read access to via
# SupplementaryGroups= - see that file's comment on why the hub needs to
# read acme-hub.env directly, not just via systemd's own EnvironmentFile=
# population at startup. -f: fine if it already exists (re-running this
# script is safe).
groupadd -f acme-hub-secrets

# Created here with the right owner/group/mode from the start, so the
# operator only ever has to edit its contents (step 2 below), never
# remember to fix its permissions - group-readable, not group-writable or
# world-anything. Left untouched if it already exists (e.g. re-running
# this script on an already-configured host).
if [ ! -e "$CONFIG_DIR/acme-hub.env" ]; then
	install -m 0640 -o root -g acme-hub-secrets /dev/null "$CONFIG_DIR/acme-hub.env"
fi

install -m 0644 "$SCRIPT_DIR/acme-hub.service" /etc/systemd/system/acme-hub.service
systemctl daemon-reload

echo "Installed acme-hub.service. Next steps:"
echo "  1. Copy deploy/hub-config.example.yaml to $CONFIG_DIR/config.yaml and edit it"
echo "     (mode 0644 is fine - no secrets in it). Spokes and DNS providers are NOT"
echo "     configured here - see step 3."
echo "  2. Edit $CONFIG_DIR/acme-hub.env (already created, mode 0640, group acme-hub-secrets)"
echo "     and set a status_token, e.g.:"
echo "       STATUS_TOKEN=..."
echo "     This is the password for GET /admin (the web admin UI) and GET /v1/status -"
echo "     leaving it unset disables both endpoints entirely. Upgrading an existing"
echo "     install? Fix acme-hub.env's permissions the same way:"
echo "       chown root:acme-hub-secrets $CONFIG_DIR/acme-hub.env && chmod 0640 $CONFIG_DIR/acme-hub.env"
echo "  3. systemctl enable --now acme-hub"
echo "  4. journalctl -u acme-hub -f"
echo "     - on first start, the hub self-signs its own TLS certificate and logs its"
echo "       sha256_fingerprint - note it down, every spoke needs to verify against it"
echo "  5. Open https://<this host>:<listen_addr port>/admin in a browser (username"
echo "     ignored, status_token as the password) to add DNS providers and spokes."
echo "     Migrating an existing config.yaml that still has spokes:/dns_providers:"
echo "     sections? Run 'acme-hub --config $CONFIG_DIR/config.yaml --import-config <old-file>'"
echo "     once instead - see ARCHITECTURE.md \"Database-backed desired state\"."
echo "  6. Copy \$(data_dir)/tls/cert.pem to each spoke as hub_tls_cert_file (see"
echo "     deploy/spoke-config.example.yaml, or use acme-spoke --load-token to skip this"
echo "     step entirely), verifying with:"
echo "       openssl x509 -in cert.pem -noout -fingerprint -sha256"
echo "     against the fingerprint logged in step 4 - plain sha256sum will NOT match"
