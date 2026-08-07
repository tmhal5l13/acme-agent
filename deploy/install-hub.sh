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

install -m 0644 "$SCRIPT_DIR/acme-hub.service" /etc/systemd/system/acme-hub.service
systemctl daemon-reload

echo "Installed acme-hub.service. Next steps:"
echo "  1. Copy deploy/hub-config.example.yaml to $CONFIG_DIR/config.yaml and edit it (mode 0644 is fine - no secrets in it)"
echo "  2. Create $CONFIG_DIR/acme-hub.env (mode 0600, root-owned) with DNS provider credentials and spoke tokens, e.g.:"
echo "       CLOUDFLARE_API_TOKEN=..."
echo "       SPOKE_FREERADIUS_TOKEN=..."
echo "  3. systemctl enable --now acme-hub"
echo "  4. journalctl -u acme-hub -f"
echo "     - on first start, the hub self-signs its own TLS certificate and logs its"
echo "       sha256_fingerprint - note it down, every spoke needs to verify against it"
echo "  5. Copy \$(data_dir)/tls/cert.pem to each spoke as hub_tls_cert_file (see"
echo "     deploy/spoke-config.example.yaml and cmd/acme-onboard), verifying with:"
echo "       openssl x509 -in cert.pem -noout -fingerprint -sha256"
echo "     against the fingerprint logged in step 4 - plain sha256sum will NOT match"
