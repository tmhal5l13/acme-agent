# acme-agent

A standalone, non-Kubernetes certificate-management system built around a
**centralized renewal hub** — the same idea as cert-manager, for
organizations that aren't running Kubernetes.

Instead of every host running its own ACME client (certbot etc.), one hub
holds your DNS provider credentials and decides when certificates are due.
Each host (a "spoke") generates its own key, drives its own ACME order, and
installs the resulting certificate itself. Private keys never leave the
host that generated them; DNS provider credentials never leave the hub.
See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the full design and why it
ended up this shape.

## Status

Working and live-tested against real infrastructure (Route53 + Let's
Encrypt staging, real TLS between hub and spoke, real systemd hardening
directives), but young. Before relying on this, know what hasn't been
exercised yet:

- **Let's Encrypt production has never been used** — every test so far has
  deliberately used staging.
- **Cloudflare, GoDaddy, and PowerDNS have only been structurally
  verified** (they construct without error); Route53 is the only DNS
  provider actually proven end-to-end.
- **Only ever tested with one spoke at a time.** The whole point of this
  architecture is many spokes against one hub, but concurrent-spoke
  behavior (including SQLite contention on the hub) is untested.
- **No real systemd deployment yet** — hardening was verified rootless
  (`systemd-run --user`) and syntax-checked (`systemd-analyze verify`) on a
  dev machine, not run as root on an actual target host.

See `ARCHITECTURE.md`'s "Known gaps" for the full list, including exactly
which packages have automated test coverage and which have only been
verified by hand.

## Quick start

Three binaries: the hub, the spoke client, and an onboarding helper.

```
go build -o /tmp/acme-hub    ./cmd/acme-hub
go build -o /tmp/acme-client ./cmd/acme-client
go build -o /tmp/acme-onboard ./cmd/acme-onboard
```

Copy `deploy/hub-config.example.yaml` and `deploy/spoke-config.example.yaml`
and fill in your DNS provider credentials, domains, and a bearer token
(`acme-onboard` will generate that token and the matching config for you —
see `ARCHITECTURE.md` → "Onboarding a spoke"). Use
`acme.environment: staging` while you're testing; Let's Encrypt's
production environment has real rate limits.

```
/tmp/acme-hub --config hub-config.yaml &
/tmp/acme-client --config spoke-config.yaml --once
```

The hub self-signs its own TLS certificate on first startup and logs its
SHA-256 fingerprint — copy that certificate to each spoke
(`hub_tls_cert_file` in its config) and verify the fingerprint before
trusting it. Full details in `ARCHITECTURE.md` → "TLS".

## Deploying for real

`deploy/` has a systemd unit, an install script, and a config example for
each long-running binary:

```
sudo ./deploy/install-hub.sh      # on the hub host
sudo ./deploy/install-client.sh   # on each spoke host
```

See `ARCHITECTURE.md` → "Production deployment (systemd)" for what these
actually set up and why the hub and spoke are hardened differently.

## License

[GNU Affero General Public License v3.0](LICENSE) — chosen deliberately
because the hub is a network service: AGPL closes the loophole plain GPL
leaves open, where someone could run a modified hub as a service without
ever being obligated to share those modifications.
