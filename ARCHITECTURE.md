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
- **`cmd/acme-spoke`** (the "spoke") — runs on each host that actually
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
  |    {domains, not_before, not_after,  |   SANs, expiry, serial, status,
  |     serial, status, error,           |   and its own local failure streak
  |     consecutive_failures}            |
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

Both sides pin `MinVersion: tls.VersionTLS13` explicitly rather than
relying on Go's own default (which has been TLS 1.2 for a long time, but
isn't guaranteed to stay wherever it currently is across future Go
upgrades) — safe to require outright since both ends of this connection
are always this project's own binaries, never a third-party TLS 1.2-only
client. `internal/hubclient`'s tests prove this is actually enforced, not
just set: a server that can't negotiate above TLS 1.2 fails the handshake.

## Package map

| Package | Used by | Purpose |
|---|---|---|
| `config` | both | YAML config loading/validation for both binaries — `HubConfig`/`LoadHubConfig` and `SpokeConfig`/`LoadSpokeConfig`, sharing a `Duration` type and `${VAR}` env-expansion for secrets |
| `internal/hubapi` | hub | HTTP handlers: bearer-token auth, per-spoke domain authorization, checkin, due, dns01 relay, notify_hook transition detection |
| `internal/hubstore` | hub | SQLite: what spokes have last reported (`spoke_cert_state`) — observed state only; desired state (domains, DNS provider, policy) lives in the hub's config, not the DB. Tracks a `schema_meta.version` and migrates an existing database forward on `Open` — see "Renewal health tracking" below |
| `internal/dnsprovider` | hub | Builds a real `lego` DNS-01 `challenge.Provider` (Route53, Cloudflare, GoDaddy, PowerDNS) from config. The one package that ever touches DNS provider credentials |
| `internal/selfsigned` | hub | Generates the hub's self-signed TLS certificate on first startup — see "TLS" above |
| `internal/onboard` | `cmd/acme-onboard` | Validates a new spoke/certificate against the hub's current config and generates the matching hub-config snippet + spoke config.yaml — see "Onboarding a spoke" below |
| `internal/hubclient` | spoke | The spoke's HTTP client for the hub's API, plus `DNS01Provider` — a `challenge.Provider` that relays `Present`/`CleanUp` through the hub instead of calling a real DNS API |
| `internal/spokeagent` | spoke | The polling loop: ask the hub if due, apply local retry backoff, run the issue/install pipeline, report back |
| `internal/acmeclient` | spoke | Drives `lego`: ACME account registration/reuse, `Issue()` |
| `internal/certwriter` | spoke | Atomically installs a certificate bundle (`privkey.pem`/`cert.pem`/`fullchain.pem`) as a unit via a versioned directory + atomic symlink swap — see "Certificate installation" |
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

Secrets are interpolated via `${VAR}` — deliberately not bare `$VAR`
(unlike `os.ExpandEnv`, which recognizes both with no way to disable one
selectively): a bare `$` in a config value shouldn't silently trigger
expansion just because it's followed by something that looks like an
identifier. An unset `${VAR}` is a load-time error naming the missing
variable, not a silent empty string — except inside a fully commented-out
line (first non-whitespace character `#`), which both example configs
above use to document optional fields without requiring their variables
to be set.

`validate()` (both configs) rejects a negative `Duration` on any field (a
single choke point in `Duration.UnmarshalYAML` covers every one), a
certificate `name` that isn't safe as a single filesystem path
component — no `/`, and not `.`/`..`, since both configs' `cert.Name`
ends up unguarded in `filepath.Join(dataDir, "certs", cert.Name)`
(`internal/spokeagent.ProcessCert`) — and a domain string that's empty,
contains whitespace/control characters, or is just a bare `*.` with
nothing after it. Deliberately loose otherwise, not a full hostname
validator: catching obvious operator typos matters more than rejecting
every technically-unusual-but-legitimate hostname.

## Local dev / manual testing

Both binaries take `--config <path>` and `--once` (run a single pass and
exit, instead of the normal polling/serving loop):

```
go build -o /tmp/acme-hub ./cmd/acme-hub
go build -o /tmp/acme-spoke ./cmd/acme-spoke

/tmp/acme-hub --config hub-dev-config.yaml &
# note the sha256_fingerprint the hub logs, then copy its cert for the spoke to pin:
cp "$(yq '.data_dir' hub-dev-config.yaml)/tls/cert.pem" ./hub-cert.pem
# set hub_tls_cert_file: ./hub-cert.pem in spoke-dev-config.yaml, then:
/tmp/acme-spoke --config spoke-dev-config.yaml --once
```

Use `acme.environment: staging` in the spoke config while testing — Let's
Encrypt's production environment has real rate limits.

## Production deployment (systemd)

`deploy/` has a unit file, install script, and config example for each
binary — `acme-hub.service`/`install-hub.sh` and
`acme-spoke.service`/`install-spoke.sh`. On the target host, after
building the binary and copying it to `/usr/local/bin/`:

```
sudo ./deploy/install-hub.sh      # or install-spoke.sh on a spoke
```

The two binaries are hardened differently on purpose:

- **The hub** runs under `DynamicUser=yes` — a fresh, unique UID systemd
  allocates just for it, with no stable username to manage. This is safe
  because the hub never execs anything else; it only makes outbound
  HTTP/DNS-provider-API calls and serves its own API.
- **The spoke** runs as a real, stable system user (`acme-spoke`, created
  by `install-spoke.sh`) instead, and does **not** set
  `NoNewPrivileges=yes` — because its reload hook typically runs
  `sudo systemctl reload ...`, and `NoNewPrivileges` would silently break
  `sudo`'s setuid-root re-exec, turning every reload into a no-op. The
  trade-off is made up for by `acme-spoke.sudoers.example`: a narrowly
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
`acme-spoke.env`, mode `0600`, root-owned) referenced from `config.yaml`
via `${VAR}` — never written into `config.yaml` itself, which is why that
file can safely stay world-readable (`0644`).

## Config hot-reload

Sending the hub process `SIGHUP` (`kill -HUP $(pidof acme-hub)`, or
`systemctl reload acme-hub`) re-reads `config.yaml` and applies it live —
no restart, no dropped connections, no in-flight request affected.

Only two things actually change this way: `spokes` and `dns_providers`
(and everything derived from them — the token→spoke index, the
`challenge.Provider` built per DNS provider). That's a deliberate, narrow
scope, not a partial implementation of "reload everything": `listen_addr`,
`tls_cert_file`/`tls_key_file`, `data_dir`, and `db_path` are all resources
already bound at process start (a listening socket, an open database file)
— `internal/hubapi` never reads any of them at all, only `cmd/acme-hub`
does, once, before the `Server` is even constructed — so there's nothing
for a reload to meaningfully change there short of a real restart.

Internally, `hubapi.Server` bundles its config, token index, and DNS
provider map into one `hubState` struct held behind an `atomic.Pointer` —
every request handler loads it once per request and reads through that
snapshot, so a reload landing mid-request can never leave a handler
looking at, say, this reload's token index paired with the previous
reload's config (the actual bug class this design rules out by
construction, verified under `-race` with concurrent readers hammering the
server while reloads happen in a loop). `Server.Reload` rebuilds the whole
`hubState` from the new config and only swaps it in if that succeeds — a
bad reload (e.g. a cert now referencing an unknown `dns_provider`) is
logged and the prior state keeps serving untouched, never partially
applied.

This is what makes low-friction spoke enrollment (see "Onboarding a
spoke") actually low-friction on the hub side too: adding a spoke no
longer means restarting the hub, just pasting the generated snippet and
sending one signal.

## Cross-platform builds

All three binaries are pure Go (no cgo — `modernc.org/sqlite` was chosen
specifically to avoid it, see `internal/store`/`internal/hubstore`), so
cross-compiling for another OS/architecture needs nothing beyond `GOOS`/
`GOARCH`, from any build machine:

```
GOOS=windows GOARCH=amd64 go build ./cmd/acme-hub
GOOS=darwin  GOARCH=arm64 go build ./cmd/acme-hub   # Apple Silicon
GOOS=darwin  GOARCH=amd64 go build ./cmd/acme-hub   # Intel - unverified, see below
```

The systemd deployment above (`deploy/`) is Linux-only and this project's
only tested production target; Windows/macOS builds exist so the code
*compiles* cleanly for anyone who wants to run a spoke there, not as a
supported deployment path with its own install tooling.

**Intel Mac (`darwin/amd64`) is explicitly deprioritized**, not actively
verified: Apple has ended (or announced ending) Intel support, so it's not
worth spending CI time or attention keeping this compiling as the codebase
evolves. It's still plain Go with no known reason it wouldn't build — the
command above should keep working — it's just not something a future
change is guaranteed to preserve, and it's not in CI's `cross-compile`
matrix below. Apple Silicon (`darwin/arm64`) is the macOS target that's
actually kept working.

Two real platform gaps to know about:

- **No process umask on Windows.** `internal/umask` restricts the process
  umask to `0077` (owner-only) before either binary creates any files —
  Unix only, via a `//go:build !windows` file. Windows has no umask
  concept at all (`syscall.Umask` isn't defined there), and file access is
  governed by ACLs inherited from the parent directory instead, which this
  project does not currently set restrictively. `umask_windows.go` is a
  deliberate no-op documenting this, not a silent gap — a Windows spoke's
  data directory permissions are whatever the parent directory's ACLs
  already grant.
- **Cross-compiled macOS binaries aren't code-signed.** `go build` run
  natively on a Mac ad-hoc-signs its own `darwin/arm64` output
  automatically; a binary cross-compiled from Linux/Windows isn't signed
  at all, and Apple Silicon's kernel refuses to execute any unsigned
  binary outright (not a dismissible Gatekeeper prompt — it won't launch).
  Run `codesign --sign - <binary>` (ad-hoc, no Apple Developer account
  needed) on the target Mac after transferring it. Intel Macs are more
  lenient about unsigned binaries, but see above — that target isn't
  actively maintained anyway.

CI's `cross-compile` job builds all three binaries for `windows/amd64` and
`darwin/arm64` on every push/PR — a `go build` check only, not a full test
run (there's no Windows/macOS runner executing the test suite) —
specifically so a future platform-incompatible call (like `syscall.Umask`
was before `internal/umask` existed) fails CI immediately instead of only
surfacing the next time someone happens to try a cross-compile by hand.
`darwin/amd64` is deliberately not in this matrix, per the Intel Mac note
above.

## Mixed DNS providers on one certificate

`SpokeCertConfig.DNSProvider` is the default `dns_providers` entry for
every domain on a cert, and covers the overwhelmingly common case where
all of a cert's domains really do share one DNS backend. It's a default,
not a hard requirement, though: ACME (RFC 8555) authorizes each SAN on a
multi-domain certificate completely independently — DNS-01 means a
separate `_acme-challenge.<domain>` lookup per domain, validated against
that domain's own authoritative DNS — the CA has no concept of "DNS
provider" and doesn't require every domain on one certificate to share
one. So one certificate legitimately can span two different DNS backends
(e.g. a primary domain on Route53 and a secondary brand domain still on
Cloudflare), and this project doesn't need to fight that.

`SpokeCertConfig.DomainDNSProviders` is the (optional, almost always
empty) per-domain override for exactly that case:

```yaml
certs:
  - name: multi-cert
    domains: [example.com, example.org]
    dns_provider: route53_main       # default: used for any domain not listed below
    domain_dns_providers:
      example.org: cloudflare_main   # this one domain uses a different provider
```

The DNS-01 relay handlers (`internal/hubapi/dns01.go`) already relay one
domain per request — the spoke's `hubclient.DNS01Provider` and lego's own
multi-SAN issuance both already call `Present`/`CleanUp` once per domain —
so resolving the provider per-domain (`resolveDNSProvider`, checking
`DomainDNSProviders` before falling back to `DNSProvider`) needed no
change anywhere else in the relay path: not `internal/acmeclient`, not
`internal/hubclient`, nothing spoke-side at all. `HubConfig.validate()`
rejects an override referencing a domain not actually in that cert's
`domains` (almost certainly a typo) or a provider not defined under
`dns_providers`, the same two checks already applied to the cert-level
`dns_provider` field. `internal/onboard`'s `Request.DomainDNSProviders`
mirrors this for the generated hub config snippet.

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
  --hub-tls-cert-file /etc/acme-spoke/hub-cert.pem \
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
| `ACME_REASON` | `no checkin since ...` (watchdog firings only — see "Hub-side staleness watchdog") |

The same `notify_hook`/`notify_timeout` also drives `RunWatchdog`'s own
firings (see "Hub-side staleness watchdog" below) — `ACME_STATUS: "stale"`
on the way in, `ACME_PREVIOUS_STATUS: "unknown"` or the recovery pair
(`"active"`/`"stale"`) on the way out — reusing this exact mechanism
rather than a second, separate notification path.

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

## ACME CA flexibility

`acme.environment` (`staging`/`production`) still selects Let's Encrypt's
own two directory URLs by default, unchanged from before this existed. But
Let's Encrypt was never a protocol requirement, just this project's
original scope — three fields on `ACMEConfig` (spoke config only; the hub
never registers an ACME account or talks to a CA directly) open that up:

- **`directory_url`** points at any ACME-compliant CA's directory
  endpoint instead — public or private (e.g. a self-hosted
  [step-ca](https://smallstep.com/docs/step-ca/) instance). Mutually
  exclusive with `environment`; `config.ACMEConfig.validate()` rejects
  both being set, since a silent "one wins" would be a confusing way to
  fail. Resolved in `internal/acmeclient.DirectoryURL`.
- **`ca_cert_file`** trusts a private CA's own TLS certificate on its ACME
  API endpoint — worth being precise that this is a *different* trust
  relationship than the certificates this project requests from that CA.
  A public CA's API endpoint is already covered by the OS trust store; a
  private CA's usually isn't, and without this, the spoke's own attempt to
  *reach* the CA over HTTPS fails before ACME's own protocol-level trust
  (the certificate being issued) is ever relevant. Built via lego's own
  exported `lego.CreateCertPool` (`internal/acmeclient.httpClientFor`),
  used for both account registration (`account.go`) and issuance
  (`manager.go`) — the same private CA gets called for both, so both need
  the same transport trust.
- **`eab_key_id` / `eab_hmac_key`** — External Account Binding (RFC 8555
  §7.3.4), required by some CAs to gate account registration: both some
  private CA setups (as a deliberate enrollment control) and some public
  ones (Google Trust Services, notably, despite being free via ACME).
  Optional, and must be set together or not at all —
  `config.ACMEConfig.validate()` enforces that pairing, since submitting
  only one to the CA would surface as a remote, harder-to-diagnose
  rejection instead of a clear local config error. When set,
  `registerAccount` (`account.go`) calls lego's
  `RegisterWithExternalAccountBinding` instead of the plain `Register` —
  a completely different registration call, not a flag on the same one.

None of this has been tested against a real non-Let's-Encrypt CA yet —
see "Known gaps."

## Certificate installation

**`reload_hook` and anything else consuming an installed certificate must
read from `<data_dir>/certs/<name>/current/{privkey.pem,cert.pem,fullchain.pem}`
— not `<data_dir>/certs/<name>/` directly.** That's a real change to the
on-disk layout, not an implementation detail: earlier versions wrote the
three files straight into `certs/<name>/`, and anything pointed at that
path directly needs updating.

The reason is bundle atomicity. `privkey.pem` only means something paired
with the `cert.pem` it was issued alongside — writing three separate
files in sequence, even with each individual write itself atomic, leaves
a real window where a crash between file N and file N+1 strands a new
key next to an old, non-matching certificate. `internal/certwriter.Write`
avoids this the standard way a whole directory's contents get swapped
atomically: the complete new bundle is written into its own versioned
directory (`certs/<name>/versions/<timestamp>-<random>/`), then `current`
is atomically repointed at it — renaming a symlink is a single-syscall
atomic replace, the same guarantee the per-file writes already relied on,
just applied to the bundle as a whole instead of to each file
individually. Nothing ever observes a partially-swapped bundle.

`certwriter.Write` itself never deletes old versions — `internal/spokeagent`'s
`ProcessCert` calls `certwriter.Prune` separately, right after a successful
`Write`, keeping the 3 most recent versions plus whichever one `current`
points at (even if that one happens to fall outside the 3 most recent —
`current` describes what's actually installed right now and is never
removed out from under it, regardless of how it got there). A `Prune`
failure is logged, not treated as an issuance failure: the new certificate
is already fully installed and usable either way. Not configurable — 3 is
a fixed default, since at roughly one renewal every 60-90 days the exact
number barely matters in practice.

## Renewal health tracking

`spoke_cert_state` carries two columns beyond what a single checkin's status
implies: `consecutive_failures` and `last_success_at`. Both exist because a
single `"failed"` checkin, on its own, can't tell an operator (or the
`renew_before` due-check) whether this is a certificate's first hiccup or
its fifteenth in a row — and with certificate lifetimes shortening (see the
CA/Browser Forum's cert-lifetime phase-down), that distinction matters more
over time, not less.

- `consecutive_failures` is the spoke's own local count (`internal/store`'s
  `MarkFailed`, incremented per attempt via SQL `RETURNING` in one round
  trip), reported to the hub on every failed checkin and reset to `0` on the
  next successful one (`CheckinActive`). The hub trusts the spoke's count
  rather than keeping its own separate tally, since the spoke is the one
  actually attempting renewal and backing off between attempts.
- `last_success_at` is set only by `CheckinActive`, never by `CheckinFailed`
  — so it stays a genuine "last time this actually worked," distinct from
  `last_checkin_at` (which updates on every checkin, successful or not).

`hubstore.Store` exposes this as two separate methods, `CheckinActive` and
`CheckinFailed`, rather than one method branching internally on status. This
split fixes a real bug an earlier single-method version had: a failed
checkin's request necessarily carries zero-valued `not_before`/`not_after`
(a spoke's `fail()` has no new certificate to report), and unconditionally
writing those over the previous row would have made the hub forget the real
expiry of whatever certificate is still installed and still valid on the
spoke. `CheckinFailed` only ever touches `status`, `last_checkin_at`,
`last_error`, and `consecutive_failures` — never the fields that describe
the certificate itself. `internal/hubstore`'s tests prove this directly:
an active checkin followed by a failed one must leave `not_before`,
`not_after`, and `serial_number` byte-for-byte unchanged. The same
correctness requirement is why `notifyIfTransitioned`'s `ACME_NOT_AFTER`
(see "Admin notifications" above) is read back from storage after the
checkin completes rather than taken from the incoming request directly — on
a transition into `"failed"`, the request's own `not_after` is legitimately
zero, but the preserved, stored value is exactly what an alert firing at
that moment needs.

`spoke_cert_state` gained these two columns via a real schema migration —
the first this project has needed. `hubstore.Open` reads
`schema_meta.version`, and if it's behind `currentSchemaVersion`, runs the
necessary `ALTER TABLE` statements and bumps the stored version, all before
the store is usable. This runs on every startup and is a no-op once a
database is already current, so there's no separate migration step to
remember to run — `internal/hubstore`'s tests cover both the upgrade path
(a hand-built pre-migration database survives with its data intact) and the
idempotent path (reopening an already-current database).

## End-to-end testing with Pebble

`internal/acmeclient/pebble_test.go` and `internal/hubapi/pebble_test.go`
exercise the real ACME protocol — account registration and certificate
issuance/renewal — against [Pebble](https://github.com/letsencrypt/pebble),
Let's Encrypt's own small local ACME test server, instead of mocking it.
This closes the gap real infrastructure testing (real Route53, real Let's
Encrypt staging) couldn't: those need real credentials and can't run
unattended, so `internal/acmeclient`'s actual `GetOrRegisterAccount`/`Issue`
calls had zero automated coverage before this. Pebble needs neither — no
DNS credentials, no network dependency on Let's Encrypt, and (unlike
staging) no rate limits, so these tests can run repeatedly and offline.

These tests are skipped, not run, by default — `go test ./...` stays green
on a machine without Pebble installed. To run them:

```
go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest
go install github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@latest
ACME_AGENT_E2E_TESTS=1 go test -run TestPebble ./internal/acmeclient/... ./internal/hubapi/...
```

Both packages launch their own Pebble + `pebble-challtestsrv` subprocesses
on the same fixed ports (Pebble's directory and `pebble-challtestsrv`'s
management API and DNS resolver aren't fully reconfigurable — its DoH
listener in particular has no disabling flag). Running both packages'
Pebble tests in the same invocation needs `go test -p 1` to serialize them;
otherwise Go's default per-package parallelism runs two Pebble instances
at once and they collide on those ports.

`internal/hubapi/pebble_test.go`'s `TestPebble_HubRelay_FullIssuance` goes
further than proving the ACME calls work — it drives a real
`hubclient.Client` over real TLS to a real `hubapi.Server`, which relays
real DNS-01 challenges to Pebble, proving the entire spoke↔hub↔CA pipeline
end to end with no fakes anywhere in the chain, not just each half tested
in isolation.

**CI** (`.github/workflows/ci.yml`) runs the full non-Pebble suite
(build/vet/gofmt/test/`-race`/`govulncheck`) on every push and pull request
against `main`, plus a separate job that installs Pebble and
`pebble-challtestsrv` and runs this Pebble-gated suite too — so none of
this depends on a human remembering to run it locally before merging.

## Hub network hardening

- **Request bodies are size-limited.** `handleCheckin` and both dns01
  handlers wrap the request body in `http.MaxBytesReader` (64KB — generous
  for these short-string payloads, not a tight fit) before decoding, so an
  authenticated-but-misbehaving spoke can't make the hub buffer an
  arbitrarily large body per request.
- **`http.Server` has real timeouts**, not Go's unbounded defaults:
  `ReadHeaderTimeout`/`ReadTimeout` bound how long a client gets to
  actually send a complete request, `IdleTimeout` bounds a kept-alive
  connection sitting idle, and `WriteTimeout` bounds the whole
  request-to-response cycle — set well above `dns_provider_timeout` (see
  below) so a legitimately-slow DNS-01 relay isn't cut off before its own
  timeout even has a chance to fire.
- **DNS provider calls are bounded**, via `HubConfig.DNSProviderTimeout`
  (default 3m, matching the spoke's own `dns01_timeout` default — both
  bound the same underlying call from either side of the relay). This
  needed a goroutine+channel wrapper (`internal/hubapi/dns01.go`'s
  `withTimeout`), not a `context.Context`: lego's `challenge.Provider`
  interface (`Present`/`CleanUp`) takes no context at all, in the pinned
  lego version, and no context-aware variant exists. **The timeout only
  stops the HTTP handler from blocking** — it has no way to actually
  cancel the underlying DNS provider call, which keeps running to
  completion or failure in the background regardless.
- **Domain-name comparison is case- and trailing-dot-normalized**
  (`domainAuthorized`) — a robustness fix, not a security one. The
  unnormalized exact-string match it replaces already failed *closed*: a
  case or trailing-dot mismatch produced a spurious 403, never let an
  unauthorized domain through. Normalizing just stops an operator's
  harmless capitalization difference between the hub's and spoke's config
  from breaking an otherwise-correctly-authorized renewal.
- **Both TLS endpoints pin `MinVersion: tls.VersionTLS13`** — see "TLS"
  above.
- **Bearer token comparison stays a plain map lookup**, deliberately not
  `crypto/subtle.ConstantTimeCompare` — see `authorize`'s doc comment in
  `internal/hubapi/auth.go` for why that pattern doesn't apply here (a map
  lookup doesn't have the byte-by-byte timing-leak shape that pattern
  exists to fix).

## Status/dashboard API

`GET /v1/status` answers a read-only, fleet-wide view of every configured
certificate's renewal health — status, failure streak, last success,
expiry — the same data previously only reachable by querying `hubstore`'s
SQLite file directly. Gated by `status_token`, a credential deliberately
separate from any spoke's own bearer token: a spoke's token only ever
authorizes it for its own certificates (`internal/hubapi.authorize`),
which would defeat the point of a *fleet-wide* view. Unlike per-spoke
tokens (a plain map lookup — see "Hub network hardening" above), the
status token comparison genuinely is `crypto/subtle.ConstantTimeCompare`,
since here there's exactly one valid value being compared directly, not a
set being looked up — the byte-by-byte timing-leak shape that primitive
exists to fix.

Left unset, `status_token` disables the endpoint entirely — `Handler()`
doesn't register the route at all, rather than registering it and always
rejecting, so it's a 404, not a 401, when unconfigured.

The response merges two sources, not just `hubstore.Store.All()` alone: a
certificate that's configured (`cfg.Spokes[*].Certs`) but has never once
checked in still appears, as `status: "unknown"` (`spoke_cert_state`'s own
default), rather than silently missing from the response just because no
row exists for it yet.

## Hub-side staleness watchdog

`notifyIfTransitioned` (see "Admin notifications" above) only fires on an
explicit `"failed"` checkin *arriving* — by construction, a spoke that
cannot reach the hub at all has no way to report that fact to the one
endpoint it can't reach. From the hub's side, a spoke silently failing to
connect looks identical to a healthy spoke with nothing due yet.
`internal/hubapi.RunWatchdog` closes that gap: a periodic, hub-initiated
scan (independent of any checkin arriving), launched by `cmd/acme-hub`
alongside the HTTP server and stopped on the same shutdown signal.

Each pass reuses `hubstore.Store.All()` (see "Status/dashboard API"
above) merged against `cfg.Spokes`, and flags a certificate stale if
either:

- it has a real `last_checkin_at`, but longer ago than
  `watchdog_stale_after` (default 2h — comfortably longer than the
  spoke's own default 15-minute `poll_interval`, so normal poll jitter or
  one slow pass never trips it) — a spoke that *was* reporting, then went
  silent; or
- it has never checked in at all, and has stayed in that state (per the
  watchdog's own tracking — there's no real timestamp to measure from
  when no checkin has ever happened) for longer than
  `watchdog_stale_after` — giving a freshly onboarded spoke the same
  grace period to actually check in for the first time that an
  already-reporting spoke gets between checkins, rather than alerting on
  the very next pass after `cmd/acme-onboard` adds it to config.

The hub can't know any individual spoke's actual configured
`poll_interval` (that's spoke-local config it never sees), so
`watchdog_stale_after` is necessarily one hub-wide threshold, not a
per-spoke one.

Firing state (which certs have already been notified, so a still-stale
one doesn't refire every single pass — the same alert-fatigue concern
`notifyIfTransitioned` already guards against on the checkin path) is
kept in memory, not persisted to `hubstore`: a hub restart clearing it
just means at most one extra notification for something still genuinely
stale, not a real problem, and it avoids coupling this feature to
`hubstore`'s own schema migration sequence. A recovery (fresh checkin
arrives for a cert the watchdog had flagged) fires a symmetric
`ACME_STATUS=active ACME_PREVIOUS_STATUS=stale` notification.

## Renewal lease/claim

Nothing previously stopped two overlapping attempts for the same
certificate from both proceeding with a real ACME order at once — e.g.
two processes of what's supposed to be one spoke running concurrently
after a botched restart, or a slow first attempt still in flight when its
own next poll tick would otherwise start a second one. `handleDue` now
closes that: answering "due" also atomically claims a renewal lease
(`hubstore.Store.Claim`), and a second caller sees "not due" for as long
as that claim is held and unexpired — even if the certificate's own
expiry would otherwise say it's due.

**The wire protocol didn't need to change at all to express this.**
`dueResponse{Due bool}` is exactly the same shape it always was — from a
caller's perspective, "due" already meant "yes, go ahead," and that
remains exactly true whether the reason for "not due" is genuinely not
due yet or someone else already has it claimed. No lease token, no
separate claim/release endpoint, nothing for the spoke to explicitly
manage.

The claim is released two ways, one primary and one as a backstop:

- **`CheckinActive`/`CheckinFailed` both release it unconditionally**, as
  part of the same statement that records the checkin — whichever the
  outcome, a completed attempt is exactly what a claim exists to guard
  against overlapping with a second one. Not identity-guarded against a
  stale, very-delayed checkin clearing a newer claim (a narrow race even
  in the scenario this exists for) — see their doc comments for why
  that's an accepted tradeoff, not an oversight: the real correctness
  guarantee is the second mechanism below, this is a responsiveness
  optimization on top of it.
- **Self-expiry via `claim_expires_at`** (`RenewalLeaseDuration`, default
  15m — comfortably longer than a real issue/renew cycle, short enough
  that a genuinely crashed spoke doesn't block retries for long) is what
  actually guarantees a claim can't block forever, including the case a
  spoke crashes mid-attempt and never checks in at all.

**`internal/spokeagent`'s local retry-backoff check moved earlier as a
direct consequence of this design**, ahead of ever calling the hub's
`/due` at all, not after — previously, backoff was checked only after the
hub had already answered "due." With claiming folded into that same
answer, checking backoff second would mean a claim the hub just granted
could sit unreleased (nothing to release it — the attempt was skipped,
never reaching a checkin) until it self-expired, potentially blocking
this same spoke's own next poll tick from claiming it for no reason.
Checking backoff first means the hub is never asked, and therefore
nothing is ever claimed, for an attempt that was never going to happen
anyway — a stronger, simpler guarantee than before, not just a
side-effect fix.

`claimed_by`/`claimed_at`/`claim_expires_at` are schema version 3 (see
"Renewal health tracking" above for the migration mechanism this
project has used since version 2 — the same pattern applies here without
changes).

## Spoke token rotation

Each spoke's `tokens` in the hub's config is a list, not a single value,
specifically so a bearer token can be rotated without a coordinated instant
cutover: both an old and a new token are valid for a spoke simultaneously
during a grace period (`internal/hubapi`'s `authorize` does one map lookup
regardless of how many tokens map to a spoke — no code cared how many
entries the list holds). Under normal operation it holds exactly one.

The workflow, using `cmd/acme-onboard`'s `PlanRotation` (`internal/onboard`):

1. Run the rotation plan for the spoke. It generates a fresh, cryptographically
   random token and prints a snippet to add *alongside* the spoke's existing
   token(s) under `spokes.<id>.tokens` in the hub's config, plus the matching
   env var to add to the hub's env file. It deliberately never reprints or
   reconstructs the spoke's *existing* token — by the time the hub's config is
   loaded, `${VAR}` references have already been expanded to literal secret
   values (see `config.expandEnv`), so there's no way to recover what env var
   name an existing token was originally written under, and printing the
   literal secret into an add-only snippet meant for pasting/logging would be
   a real way to leak it.
2. Add that line and env var, restart the hub — both tokens are now valid.
3. Update the spoke's own `hub_token` to the new value, restart the spoke,
   confirm it's actually working (a successful `/due` poll is enough).
4. Remove the old token line from the hub's config and its env file, restart
   the hub again to complete the rotation — only the new token authenticates
   from this point on.

The new token's env var name can't just be `envVarName(spokeID)` (what a
fresh onboard would generate) — that would collide with the existing token's
own env var name while both need to coexist as distinct `${VAR}` references
during the grace period. `PlanRotation` appends a short random hex suffix to
keep the two apart.

## Hub TLS certificate rotation

Rotating the hub's self-signed certificate (see "TLS" above) needs **no code
change** to `internal/hubclient`, because `crypto/x509.CertPool.AppendCertsFromPEM`
— what `hubclient.New` already calls to build its trust pool — accepts a PEM
blob containing more than one certificate concatenated together, and a
`CertPool` can be built from that in one call. A spoke's `hub_tls_cert_file`
can therefore hold both the hub's current certificate and a "next" one at
once, and it'll trust a TLS handshake presenting either (`internal/hubclient`'s
`TestNew_TrustsMultipleConcatenatedCerts` proves this directly against two
real listeners, not just that `AppendCertsFromPEM`'s docs claim it).

The one new primitive this needed: `internal/selfsigned.GenerateCert`, an
*unconditional* certificate generator — unlike `EnsureCert`, which only fills
in a missing cert/key pair and leaves an existing one untouched (the property
that keeps a normal hub restart from invalidating every spoke's pinned copy),
`GenerateCert` always produces a fresh one, which is exactly what's needed to
generate a "next" candidate cert into a new path without touching the one
currently in service.

The manual rotation procedure:

1. Generate a "next" cert/key pair into new paths (e.g.
   `internal/selfsigned.GenerateCert("/var/lib/acme-hub/tls/cert-next.pem",
   ".../key-next.pem", host)` — there's no CLI flag for this yet, it's a
   one-off script/manual step).
2. Concatenate the current and next certificates into each spoke's
   `hub_tls_cert_file` (`cat cert.pem cert-next.pem > combined-cert.pem` on
   the hub, then copy `combined-cert.pem` out to every spoke, replacing what
   they had). Restart each spoke so it picks up the combined trust file — no
   hub restart needed yet, it's still serving the old cert throughout this
   step.
3. Once every spoke has confirmed it's working against the hub while trusting
   both certs, replace `tls_cert_file`/`tls_key_file`'s contents with the
   "next" pair and restart the hub — it now presents the new certificate,
   which every spoke already trusts, so this cutover doesn't require another
   round of spoke restarts.
4. Once confirmed, spokes' trust files can be trimmed back down to just the
   new certificate alone (optional cleanup, not required for correctness).

## Known gaps

- **Test coverage exists for `internal/hubapi`** (auth boundary including
  that a near-miss bearer token is rejected exactly like an unrelated one,
  per-cert domain authorization including case/trailing-dot normalization,
  checkin including input validation, oversized-body rejection, and
  implausible-lifetime rejection, due including per-cert policy override,
  dns01 relay including that a provider call that never returns is bounded
  by `DNSProviderTimeout` rather than hanging the handler forever,
  notify_hook transition detection including that a failed checkin's
  notification carries the certificate's real preserved expiry, not a
  zero value, the status API including that a spoke's own token doesn't
  also work there and that a never-checked-in cert still appears, and
  the staleness watchdog including that it doesn't refire every pass for
  a still-stale cert, that recovery fires a symmetric notification, and
  that a never-checked-in cert gets the same grace period a real checkin
  history would, the renewal lease including that a second `/due`
  call while a claim is held reports not-due and that a released claim
  (via checkin) is immediately claimable again, and token rotation
  including that a spoke with two tokens configured authenticates with
  either one, not just the first — all via real HTTP
  requests against a real temp-file SQLite store, with a fake
  `challenge.Provider` standing in for a real DNS API, and (for the
  claim specifically) against real Pebble/`pebble-challtestsrv`
  end-to-end — see "End-to-end testing with Pebble" above — proving it
  prevents an actual duplicate real issuance, not just that the
  underlying SQL is atomic in isolation),
  **`internal/hubstore`** (the `CheckinActive`/`CheckinFailed` split that
  keeps a failed renewal from erasing a still-valid certificate's known
  expiry, the failure-streak/last-success tracking, `All`'s fleet-wide
  enumeration, `Claim`'s atomicity under real concurrent goroutines (not
  just assumed from the SQL), and the `schema_meta` migration path
  against hand-built pre-migration databases at each version),
  **`internal/spokeagent`** (backoff math, cert-time parsing, the local
  backoff-skip decision via a fake hub over `httptest`), **`internal/onboard`**
  (including a round-trip through the real config loader, and
  `PlanRotation` — a fresh token distinct from the spoke's existing one,
  a collision-free env var name, and that its output never leaks the
  spoke's existing token value), **`internal/hubclient`**
  (real TLS handshakes against a real listener using a real
  `internal/selfsigned` certificate — including that a client pinned to
  the *wrong* certificate is actually rejected, that a server unable to
  negotiate above TLS 1.2 is rejected too, not just that TLS is nominally
  on, and that a trust file holding two concatenated certificates accepts
  a handshake presenting either one — the mechanism hub TLS rotation
  relies on), **`internal/selfsigned`** (SAN correctness for both IP
  and DNS hosts, key file permissions, `EnsureCert`'s idempotency across
  restarts, and `GenerateCert`'s unconditional-overwrite behavior — the
  opposite property, needed for rotation),
  **`internal/certwriter`** (bundle-swap atomicity via the `current`
  symlink, permissions, that a renewal fully replaces what `current`
  resolves to without touching the prior version's own files, and that
  `Prune` never deletes whatever `current` points at regardless of its
  age), `config` (loading/validation for both `HubConfig` and `SpokeConfig`
  — the mutual-exclusivity and pairing rules around ACME CA flexibility,
  see above, plus negative-`Duration` rejection, cert-name path-safety,
  domain well-formedness, and that `${VAR}`-only expansion actually
  excludes bare `$VAR` and errors on a real unset reference while leaving
  commented-out documentation alone — including round-trips through both
  `deploy/*.example.yaml` files with real env vars set, not just
  hand-built config structs), `internal/acmeclient`
  (directory URL resolution for `environment` vs `directory_url`,
  private-CA trust, and — gated behind `ACME_AGENT_E2E_TESTS`, see
  "End-to-end testing with Pebble" below — the actual
  `GetOrRegisterAccount`/`Issue` ACME protocol calls against a real local
  ACME server, including the full spoke↔hub↔CA relay path), `internal/hook`,
  and `internal/dnsprovider`. `internal/store` has some coverage now too
  (WAL/busy_timeout takes effect, `GetAccount`'s not-found path) but far
  less than `internal/hubstore`'s. `cmd/acme-hub` has targeted coverage for
  `ensureTLS` (SAN correctness including the wildcard-`listen_addr`
  fallback) and `watchForReload` (a real self-sent `SIGHUP` against a real
  `hubapi.Server`, proving the signal plumbing itself works, not just
  `Server.Reload` in isolation) — everything else, the remaining
  `internal/store` surface, and `cmd/acme-spoke`/`cmd/acme-onboard` in
  full, has been verified only by running real binaries against real
  infrastructure (a real Route53 zone, Let's Encrypt staging) during
  development, not by `go test`.
- **Hot-reload is partial, not total.** See "Config hot-reload" above —
  `spokes` and `dns_providers` apply live via `SIGHUP`, but `listen_addr`,
  the TLS cert paths, `data_dir`, and `db_path` still require a real
  restart, since they're resources already bound at process start that
  nothing in `internal/hubapi` ever re-reads anyway.
- **Behavior at high spoke counts is unverified.** Two concentration
  points exist by design, both worth naming explicitly rather than
  leaving implicit: `internal/hubstore`'s SQLite backend serializes
  writes (every checkin is one, regardless of how many spokes are
  checking in concurrently) — `hubstore.Open`/`store.Open` set WAL journal
  mode and a 5s `busy_timeout` specifically so a write waits for a
  concurrent one to finish rather than failing immediately with
  `SQLITE_BUSY`, but there's still one real bottleneck underneath: only
  one writer at a time — and every spoke's DNS-01 challenge relays
  through the hub to the actual DNS provider, whose own API rate limits
  this project has no control over. `ACMEDefaultsConfig.RenewalJitter`
  spreads *when* certificates come due specifically to avoid all of them
  clustering on the same renewal window, but it doesn't raise either
  ceiling — it only reduces how often the fleet is likely to approach
  them at once. This project's own testing has only ever run 2 spokes
  concurrently, nowhere near enough to know where the real limit is. One
  factor cuts the other direction, though: each spoke registers and owns
  its own ACME account (see the package map's `internal/store` and
  `internal/acmeclient` rows above) rather than sharing one centrally,
  which spreads exposure to Let's Encrypt's own per-account rate limits
  across accounts instead of concentrating it the way a single shared
  account would.
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
- **Self-reported checkin fields aren't cryptographically verified.**
  `handleCheckin` trusts `not_before`/`not_after`/`serial` exactly as a
  spoke reports them — the hub has no independent way to confirm they
  correspond to a real certificate at all, short of the spoke submitting
  the certificate itself (e.g. a SHA-256 fingerprint the hub could verify
  independently, not just self-reported fields). Concretely: a spoke with
  a stolen or leaked bearer token could suppress renewal indefinitely by
  reporting a far-future `not_after` on every checkin, since `handleDue`'s
  renewal-due calculation trusts it verbatim. `checkinRequest.validate()`
  mitigates the specific far-future version of this — rejecting a
  `not_after` more than 398 days past `not_before`, the longest lifetime
  any public CA is currently permitted to issue — but a spoke can still
  lie within that plausible range. Closing this fully needs the stronger
  fix described above, not just a sanity bound.
- **No certificate-revocation checking.** Nothing currently checks whether
  an installed certificate has been revoked; a revoked certificate would
  only be replaced on its normal renewal schedule. Let's Encrypt's OCSP
  responders are fully retired (as of August 2025) in favor of CRLs, so
  this would need to be CRL-based — fetching the CRL named in the
  certificate's own `crlDistributionPoints` extension and checking the
  certificate's serial against it.
- **Only one AWS identity per hub for Route53** — deliberate, not an
  oversight. `internal/dnsprovider.New`'s `"route53"` case passes no
  credentials of its own; `route53.NewDNSProviderConfig` resolves them via
  the AWS SDK's own default chain (environment, `~/.aws/credentials`, or
  an IAM role), which is exactly what the config's own comment on
  `HostedZoneID`/`Region` documents — no `access_key_id`/`secret_access_key`
  fields exist on purpose, per AWS's own guidance against long-lived keys
  in application config. The consequence, a logical entailment of that
  choice rather than something separately decided: since credential
  resolution happens once per process, every `route53_*` entry in the
  hub's config resolves to the same AWS identity, however many are
  defined. This only matters for Route53 zones split across AWS accounts
  that can't be unified under one IAM principal — one account with
  multiple zones, scoped via one policy across several hosted-zone ARNs,
  is unaffected. Every other provider (Cloudflare, GoDaddy, PowerDNS,
  rfc2136) takes its credentials directly from its own named config
  entry, independent of the process environment, so multiple distinct
  credential sets for those providers already work today without any
  code change.
- **CA flexibility (`directory_url`, `ca_cert_file`, EAB — see "ACME CA
  flexibility" above) is implemented but has never been exercised against
  a real non-Let's-Encrypt CA.** Every live test in this project's history
  has used Let's Encrypt staging. The new code paths (custom directory
  URL, private-CA transport trust, `RegisterWithExternalAccountBinding`)
  are unit-tested in isolation, but nothing has actually registered an
  account or issued a certificate against a second CA end-to-end.
