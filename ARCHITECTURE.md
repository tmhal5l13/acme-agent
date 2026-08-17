# Architecture

acme-agent is a standalone, non-Kubernetes reimplementation of cert-manager's
certificate pipeline, built as a **centralized renewal hub** for an
organization's certificates — replacing per-host ACME clients (certbot etc.)
rather than just being one more of them.

## Why two binaries

Two designs were tried before this one and rejected:

1. **Single-host agent.** One process issues and installs certs for itself.
   Works, but is materially just certbot with a nicer config/state layer —
   nothing distributes certs beyond the host running the agent.
2. **Hub pushes cert material to spokes over SSH/SFTP.** Rejected: it moves
   private key material off the host that generated it, and makes the hub a
   high-value target needing standing credentialed access to every spoke.

The current design instead splits the work across two binaries so that
**private keys never leave the host that generates them**, and **DNS
provider credentials never leave the hub**:

- **`cmd/acme-hub`** — the centralized authority. Tracks what certificates
  spokes have (via their own reports), decides when each is due for
  renewal, and holds every DNS provider credential. It never holds a
  private key or a signed certificate.
- **`cmd/acme-client`** (the "spoke") — runs on each host that actually
  needs a certificate. Generates its own key, drives its own ACME order,
  installs the resulting certificate locally, and runs its own local
  reload hook (e.g. `systemctl reload nginx`).

A spoke polls the hub — the hub never opens a connection to a spoke — so the
hub needs no credentials or inbound access for any individual spoke, and the
whole thing works through NAT with no inbound firewall rule needed on the
spoke side.

## Request flow

```
spoke                                   hub
  |--- GET /v1/certs/{name}/due -------->|   hub checks its last-known
  |<-------------- {due: true} ----------|   expiry for this spoke+cert
  |
  |  (spoke starts its own ACME order directly with Let's Encrypt,
  |   generating its own key and CSR — the hub is not involved yet)
  |
  |--- POST /v1/certs/{name}                  hub authorizes the domain
  |         /dns01/present ------------->|    against this spoke's config,
  |    {domain, token, key_auth}         |    then calls the real DNS
  |<------------- 204 --------------------|   provider's Present()
  |
  |  (spoke tells Let's Encrypt the challenge is ready; Let's Encrypt
  |   validates the TXT record directly against the DNS provider)
  |
  |--- POST /v1/certs/{name}/dns01/cleanup --->|  same relay, CleanUp()
  |
  |  (spoke receives the signed certificate directly from Let's Encrypt,
  |   writes it to local disk, runs its local reload hook)
  |
  |--- POST /v1/certs/{name}/checkin --->|   spoke reports what it now has:
  |    {domains, not_before, not_after,  |   SANs, expiry, serial, status
  |     serial, status, error}           |
```

Only a bearer token (proving spoke identity) and an ACME challenge token
(meaningless outside that one validation) ever cross from spoke to hub.
Never a private key, never a DNS credential. Every request in this diagram
runs over TLS — see below.

## TLS

The hub has no public DNS name of its own (it's an internal-only service),
so there's no certificate authority to issue it a normal certificate —
which means it can't just get a Let's Encrypt cert the way it gets one for
spokes. Instead, `cmd/acme-hub` self-signs its own certificate on first
startup if one doesn't already exist at `tls_cert_file`/`tls_key_file`
(`internal/selfsigned`), and every spoke is given a copy of that exact
certificate to trust directly (`hub_tls_cert_file` in the spoke's config,
consumed by `internal/hubclient`) — the same role an SSH `known_hosts`
entry plays, not a certificate authority relationship. This is real
pinning via `tls.Config{RootCAs: pool}`, never `InsecureSkipVerify`; a
spoke pinned to the wrong certificate fails the TLS handshake outright
(`internal/hubclient`'s tests prove this directly, not just that TLS is
nominally enabled).

Because regenerating the certificate would invalidate every spoke's pinned
copy, `internal/selfsigned.EnsureCert` is idempotent — it only generates
one if the configured paths don't already have one, never on top of an
existing one, so a hub restart doesn't quietly break every spoke.

The certificate's SAN comes from `listen_addr`'s host by default, since
that's normally also the address spokes dial. That breaks for a wildcard
bind (`listen_addr: "0.0.0.0:8443"`, listening on every interface) — the
generated certificate would be issued for the meaningless identity
`0.0.0.0`, and Go's TLS client verifies the certificate against the address
it actually dialed, so every spoke's handshake fails outright (`remote
error: tls: bad certificate`, logged hub-side). `tls_host` overrides the
SAN independently of `listen_addr` for exactly this case — set it to the
real hostname or IP spokes connect through.

The hub logs its certificate's SHA-256 fingerprint on every startup
(`hub TLS certificate ready sha256_fingerprint=...`) — verify a copied
certificate against it with:

```
openssl x509 -in hub-cert.pem -noout -fingerprint -sha256
```

Plain `sha256sum hub-cert.pem` will **not** match — it hashes the raw PEM
file's text encoding, not the parsed certificate bytes the fingerprint
above is computed from.

## Package map

| Package | Used by | Purpose |
|---|---|---|
| `config` | both | YAML config loading/validation for both binaries — `HubConfig`/`LoadHubConfig` and `SpokeConfig`/`LoadSpokeConfig`, sharing a `Duration` type and `${VAR}` env-expansion for secrets |
| `internal/hubapi` | hub | HTTP handlers: bearer-token auth, per-spoke domain authorization, checkin, due, dns01 relay, notify_hook transition detection |
| `internal/hubstore` | hub | SQLite: what spokes have last reported (`spoke_cert_state`) — observed state only; desired state (domains, DNS provider, policy) lives in the hub's config, not the DB |
| `internal/dnsprovider` | hub | Builds a real `lego` DNS-01 `challenge.Provider` (Route53, Cloudflare, GoDaddy, PowerDNS) from config. The one package that ever touches DNS provider credentials |
| `internal/selfsigned` | hub | Generates the hub's self-signed TLS certificate on first startup — see "TLS" above |
| `internal/onboard` | `cmd/acme-onboard` | Validates a new spoke/certificate against the hub's current config and generates the matching hub-config snippet + spoke config.yaml — see "Onboarding a spoke" below |
| `internal/hubclient` | spoke | The spoke's HTTP client for the hub's API, plus `DNS01Provider` — a `challenge.Provider` that relays `Present`/`CleanUp` through the hub instead of calling a real DNS API |
| `internal/spokeagent` | spoke | The polling loop: ask the hub if due, apply local retry backoff, run the issue/install pipeline, report back |
| `internal/acmeclient` | spoke | Drives `lego`: ACME account registration/reuse, `Issue()` |
| `internal/certwriter` | spoke | Atomically writes `privkey.pem`/`cert.pem`/`fullchain.pem` to disk with correct permissions (`0600`/`0644`) |
| `internal/hook` | both | Runs an operator-configured shell command bounded by a timeout (`Cmd.WaitDelay` — see the package for why a plain context timeout isn't enough): a certificate's `reload_hook` (spoke) or the hub's `notify_hook` (hub) |
| `internal/store` | spoke | SQLite: the spoke's own ACME account + its local view of what it currently has installed |

`internal/store` (spoke) and `internal/hubstore` (hub) are deliberately
separate packages with different schemas, not one shared "store" — they
track different things (a spoke's own installed certs vs. a hub's inventory
of every spoke's reported state) and evolving one should never risk breaking
the other.

## Config

See `deploy/hub-config.example.yaml` and `deploy/spoke-config.example.yaml`
for fully-commented examples. The one identifier that must match exactly
across both files is a certificate's `name` — it's how the hub's
per-cert authorization (`spokes.<id>.certs[].name`) lines up with what a
spoke asks for (`certs[].name`).

## Local dev / manual testing

Both binaries take `--config <path>` and `--once` (run a single pass and
exit, instead of the normal polling/serving loop):

```
go build -o /tmp/acme-hub ./cmd/acme-hub
go build -o /tmp/acme-client ./cmd/acme-client

/tmp/acme-hub --config hub-dev-config.yaml &
# note the sha256_fingerprint the hub logs, then copy its cert for the spoke to pin:
cp "$(yq '.data_dir' hub-dev-config.yaml)/tls/cert.pem" ./hub-cert.pem
# set hub_tls_cert_file: ./hub-cert.pem in spoke-dev-config.yaml, then:
/tmp/acme-client --config spoke-dev-config.yaml --once
```

Use `acme.environment: staging` in the spoke config while testing — Let's
Encrypt's production environment has real rate limits.

## Production deployment (systemd)

`deploy/` has a unit file, install script, and config example for each
binary — `acme-hub.service`/`install-hub.sh` and
`acme-client.service`/`install-client.sh`. On the target host, after
building the binary and copying it to `/usr/local/bin/`:

```
sudo ./deploy/install-hub.sh      # or install-client.sh on a spoke
```

The two binaries are hardened differently on purpose:

- **The hub** runs under `DynamicUser=yes` — a fresh, unique UID systemd
  allocates just for it, with no stable username to manage. This is safe
  because the hub never execs anything else; it only makes outbound
  HTTP/DNS-provider-API calls and serves its own API.
- **The spoke** runs as a real, stable system user (`acme-client`, created
  by `install-client.sh`) instead, and does **not** set
  `NoNewPrivileges=yes` — because its reload hook typically runs
  `sudo systemctl reload ...`, and `NoNewPrivileges` would silently break
  `sudo`'s setuid-root re-exec, turning every reload into a no-op. The
  trade-off is made up for by `acme-client.sudoers.example`: a narrowly
  scoped sudoers rule authorizing exactly the reload command(s) this spoke
  needs, nothing broader.

`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, and
`MemoryDenyWriteExecute` were verified directly against this project's
compiled binaries (pure Go, no cgo) via rootless `systemd-run --user`
transient units during development — each started, bound its port, and
served real requests under all of them together. The remaining directives
in both unit files are standard `systemd.exec(5)` hardening that could not
be verified the same way (several require `CAP_SETPCAP`, which an
unprivileged user session doesn't have — a limitation of rootless testing,
not a sign of incompatibility), but apply correctly under the real
root-managed system units these files describe.

Secrets for both binaries live in an `EnvironmentFile` (`acme-hub.env` /
`acme-client.env`, mode `0600`, root-owned) referenced from `config.yaml`
via `${VAR}` — never written into `config.yaml` itself, which is why that
file can safely stay world-readable (`0644`).

## Onboarding a spoke

`cmd/acme-onboard` exists because hand-editing two separate YAML files (the
hub's `spokes.<id>.certs[].name` and the spoke's own `certs[].name`) to keep
a matching name and a matching token was the actual friction point in
adding a new spoke — a typo in either file produces a silent `403` the
first time the real spoke tries to use it, not a helpful error at edit
time.

The tool never edits the hub's config itself (YAML round-tripping through
`gopkg.in/yaml.v3` would strip comments and reformat the file, so this is
deliberate, not a missing feature) — it loads the hub's *current* config
read-only, validates the request against it, and prints exactly what to
paste:

```
go build -o /usr/local/bin/acme-onboard ./cmd/acme-onboard

acme-onboard \
  --hub-config /etc/acme-hub/config.yaml \
  --spoke-id freeradius-spoke \
  --cert-name radius-cert \
  --domains radius.example.com \
  --dns-provider route53_main \
  --hub-url https://192.0.2.10:8443 \
  --hub-tls-cert-file /etc/acme-client/hub-cert.pem \
  --reload-hook "systemctl restart freeradius" \
  --acme-email admin@example.com \
  --acme-environment staging \
  --spoke-config-out ./radius-spoke-config.yaml
```

This prints the `spokes:` block to paste into the hub's `config.yaml`, the
`${VAR}=...` line to add to `acme-hub.env`, and writes the new spoke's
complete `config.yaml` to the given path — all sharing one freshly
generated 256-bit token (`crypto/rand`), so the two files can't drift. It
also reminds you to copy the hub's certificate to `--hub-tls-cert-file` on
the new spoke and verify its fingerprint (see "TLS" above) — that step
still has to happen out-of-band, since the tool has no access to the
spoke's filesystem. Running it again with an existing `--spoke-id` and a
new `--cert-name` adds a second certificate to that spoke and reuses its
existing token instead of generating (and thereby invalidating) a new one.

Validated in `internal/onboard`'s tests by writing the generated spoke
config to a file and loading it through the real `config.LoadSpokeConfig`
— not just checking the YAML looks right — and, during development, by
running the actual built binary against a hub config that started with
zero spokes, applying its exact printed output, and completing a real
issuance against Let's Encrypt staging with it.

## Admin notifications

The hub's optional `notify_hook` (mirrors a certificate's `reload_hook` —
same `internal/hook` package, an arbitrary shell command, no hardcoded
notification backend) fires when a certificate's status *transitions*:
into `"failed"` (alert) or from `"failed"` back to `"active"` (resolved).
It does not fire on every checkin — a spoke that's already failing keeps
checking in `"failed"` on its own retry schedule (see `internal/spokeagent`
backoff), and re-notifying on each one would be alert fatigue with no new
information.

The command runs synchronously as part of handling the checkin request,
bounded by `notify_timeout` (default 30s) — so a slow notify command adds
that much latency to that one checkin, never more, and never blocks other
spokes' requests (`net/http`'s server handles each concurrently). Context
is passed via environment variables rather than command-line arguments,
so the operator's script can use whichever pieces it needs:

| Variable | Example |
|---|---|
| `ACME_SPOKE` | `freeradius-spoke` |
| `ACME_CERT` | `radius-cert` |
| `ACME_STATUS` | `failed` |
| `ACME_PREVIOUS_STATUS` | `active` |
| `ACME_ERROR` | `issue certificate: obtain certificate: ...` |
| `ACME_NOT_AFTER` | `2026-11-04T07:50:21Z` (RFC3339; last known good expiry) |

```yaml
notify_hook: "/etc/acme-hub/notify.sh"   # e.g. curl a webhook, or `mail -s ...`
notify_timeout: 30s
```

`internal/hubapi`'s tests cover the transition logic directly — including
that three consecutive `"failed"` checkins in a row fire the hook exactly
once, not three times, and that a `"failed"` → `"active"` recovery fires a
second time with the reversed status pair.

## Renewal jitter

Let's Encrypt's own client-listing requirements ask that clients "perform
routine renewals at randomized times, or encourage that configuration" —
so that many independent installations don't all converge on renewing at
the same predictable moment and spike Let's Encrypt's (and your DNS
provider's) infrastructure. Without this, a fleet of certificates issued
around the same time would all cross their `renew_before` threshold on the
same day, generating a burst against the hub, the DNS provider, and Let's
Encrypt all at once.

`acme_defaults.renewal_jitter` (default `48h`) adds a stagger to *when*
each certificate starts being considered due — computed in `handleDue`
(`internal/hubapi/jitter.go`), not per-spoke, since the hub is the
scheduling authority. Two properties make this safe rather than just
random:

- **Only ever earlier, never later.** Jitter is *added* to `renew_before`,
  widening the window rather than shifting it — a certificate can become
  due somewhat ahead of the configured threshold, never behind it. It
  can't erode the safety margin `renew_before` was set to guarantee.
- **Stable per certificate, not re-rolled per request.** The jitter for a
  given spoke+cert is deterministic (`hash(spokeID + "/" + certName)`
  mapped into `[0, renewal_jitter)`), so the same certificate always gets
  the same offset. A random value re-rolled on every `/due` call would
  make a certificate's due status flip-flop between polls — this
  guarantees different certificates spread out relative to each other
  while any single certificate's due-ness is consistent from one check to
  the next.

Like every other `Duration` field in this config, `0` means "unset, use
the default" rather than "explicitly disabled" — there's no way to fully
turn jitter off, only make it negligible with a very small nonzero value.

## Known gaps

- **Test coverage exists for `internal/hubapi`** (auth boundary, per-cert
  domain authorization, checkin, due including per-cert policy override,
  dns01 relay, notify_hook transition detection — all via real HTTP
  requests against a real temp-file SQLite store, with a fake
  `challenge.Provider` standing in for a real DNS API), **`internal/spokeagent`**
  (backoff math, cert-time parsing, the local backoff-skip decision via a
  fake hub over `httptest`), **`internal/onboard`** (including a round-trip
  through the real config loader), **`internal/hubclient`** (real TLS
  handshakes against a real listener using a real `internal/selfsigned`
  certificate — including that a client pinned to the *wrong* certificate
  is actually rejected, not just that TLS is nominally on),
  **`internal/selfsigned`** (SAN correctness for both IP and DNS hosts,
  key file permissions, idempotency across restarts), `internal/hook`, and
  `internal/dnsprovider`. Everything else — `internal/store`,
  `internal/acmeclient`, `internal/certwriter`, and all three `cmd/`
  binaries — has been verified only by running real binaries against a
  real Route53 zone and Let's Encrypt staging during development, not by
  `go test`.
- **No hot-reload.** Both `acme-onboard` output and a hand-edit alike
  require restarting the hub to take effect — config is loaded once at
  startup.
- **GoDaddy is blocked on an upstream `lego` limitation, not just
  untested.** GoDaddy's modernized API requires a Bearer-token Personal
  Access Token; `lego`'s GoDaddy provider (checked against both the
  version this project pins and `lego`'s current upstream master) only
  ever sends the legacy `sso-key` credential format against GoDaddy's v1
  endpoints. Getting PAT support would mean `lego` migrating to GoDaddy's
  v3 API entirely (different endpoint paths and response shapes, not just
  a different auth header) — real provider work upstream, not a config
  change here.
- **`reload_hook` and `notify_hook` are both unit-tested only.** Neither
  has been exercised against a real consuming service or a real firing in
  a live deployment. `notify_hook`'s transition-detection logic has run
  for real (a genuine "failed" checkin occurred during development), but
  no hook was configured at the time to confirm the actual invocation
  path.
- **No hub-side staleness/expiry watchdog.** `notifyIfTransitioned` (see
  "Admin notifications" above) only fires on an explicit "failed" checkin
  arriving — by construction, a spoke that cannot reach the hub at all has
  no way to report that fact to the one endpoint it can't reach. From the
  hub's side, a spoke silently failing to connect looks identical to a
  healthy spoke with nothing due yet. Closing this needs a periodic,
  hub-initiated scan of `hubstore` for certificates whose expiry is
  getting close or whose `last_checkin_at` is stale relative to how often
  that spoke should be polling, independent of any checkin arriving.
- **No certificate-revocation checking.** Nothing currently checks whether
  an installed certificate has been revoked; a revoked certificate would
  only be replaced on its normal renewal schedule. Let's Encrypt's OCSP
  responders are fully retired (as of August 2025) in favor of CRLs, so
  this would need to be CRL-based — fetching the CRL named in the
  certificate's own `crlDistributionPoints` extension and checking the
  certificate's serial against it.
- **The ACME CA is hardcoded to Let's Encrypt.** `internal/acmeclient`'s
  directory-URL selection only recognizes `"staging"`/`"production"`,
  mapped to Let's Encrypt's own two directory URLs — there's no way to
  point this project at a different ACME CA (public or private), no way
  to trust a private CA's own TLS certificate on its API endpoint (a
  different trust relationship than the certificates being issued), and
  no External Account Binding (EAB) support, which some CAs require for
  account registration regardless of CA type.
