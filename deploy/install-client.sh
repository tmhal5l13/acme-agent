#!/usr/bin/env bash
# Installs the acme-client systemd unit, dedicated system user, and config
# directory on this host. Run as root, after building acme-client and
# copying it to /usr/local/bin.
set -euo pipefail

BINARY=/usr/local/bin/acme-client
CONFIG_DIR=/etc/acme-client
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
	echo "run as root" >&2
	exit 1
fi

if [ ! -x "$BINARY" ]; then
	echo "expected $BINARY to exist and be executable - copy the built acme-client binary there first" >&2
	exit 1
fi

# Unlike the hub (DynamicUser), this needs a real, stable, nameable system
# user - see acme-client.service and acme-client.sudoers.example for why.
if ! id acme-client >/dev/null 2>&1; then
	useradd --system --no-create-home --shell /usr/sbin/nologin acme-client
fi

# config.yaml holds no secrets (only \${VAR} placeholders, expanded from
# acme-client.env), so it doesn't need to be readable only by acme-client.
install -d -m 0755 "$CONFIG_DIR"

install -m 0644 "$SCRIPT_DIR/acme-client.service" /etc/systemd/system/acme-client.service
systemctl daemon-reload

echo "Installed acme-client.service and the acme-client system user. Next steps:"
echo "  1. Copy deploy/spoke-config.example.yaml to $CONFIG_DIR/config.yaml and edit it (mode 0644 is fine - no secrets in it)"
echo "  2. Create $CONFIG_DIR/acme-client.env (mode 0600, root-owned) with this spoke's hub token, e.g.:"
echo "       HUB_TOKEN=..."
echo "  3. Copy the hub's TLS certificate here as hub_tls_cert_file (see config.yaml's"
echo "     hub_tls_cert_file path), verifying its fingerprint first:"
echo "       openssl x509 -in hub-cert.pem -noout -fingerprint -sha256"
echo "     against what the hub logged on its own startup - plain sha256sum will NOT match"
echo "  4. Set up the reload-hook sudoers rule - see acme-client.sudoers.example"
echo "  5. systemctl enable --now acme-client"
echo "  6. journalctl -u acme-client -f"
