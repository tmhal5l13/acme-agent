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
| `internal/hubapi` | hub | HTTP handlers: bearer-token auth, per-spoke domain authorization, checkin, due, dns01 relay, notify_hook transition detection, read-only admin dashboard |
| `internal/hubstore` | hub | SQLite: both what spokes have last reported (`spoke_cert_state` — observed state) and, since "Database-backed desired state" below, which spokes/DNS providers exist and what they're authorized for (`spokes`, `spoke_tokens`, `spoke_certs`, `dns_providers` — desired state). Tracks a `schema_meta.version` and migrates an existing database forward on `Open` — see "Renewal health tracking" below |
| `internal/dnsprovider` | hub | Builds a real `lego` DNS-01 `challenge.Provider` (Route53, Cloudflare, GoDaddy, PowerDNS) from config. The one package that ever touches DNS provider credentials |
| `internal/selfsigned` | hub | Generates the hub's self-signed TLS certificate on first startup — see "TLS" above |
| `internal/onboard` | `cmd/acme-onboard`, `cmd/acme-hub --generate-token` | Validates a new spoke/certificate, writes it directly into the hub's database (`internal/hubstore`), and generates the spoke's own config.yaml — see "Onboarding a spoke" below |
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

Secrets for both binaries live in a separate env file (`acme-hub.env` /
`acme-spoke.env`) referenced from `config.yaml` via `${VAR}` — never
written into `config.yaml` itself, which is why that file can safely stay
world-readable (`0644`). `acme-spoke.env` stays `0600` root-owned,
populated the standard way via `EnvironmentFile=`; `acme-hub.env` is
`0640`, group `acme-hub-secrets` — see "Config hot-reload" below for why
the hub's case needs more than that.

## Production deployment (Windows service)

The spoke — not the hub, which stays a Linux-only deployment target — can
also run as a real, registered Windows service instead of a bare console
process:

```
deploy\install-spoke.ps1 -BinaryPath C:\...\acme-spoke.exe -ConfigPath C:\...\config.yaml
```

`internal/winservice` (a `//go:build` split, no-op everywhere but Windows)
is what makes this work: `cmd/acme-spoke/main.go` calls
`winservice.RunIfService(stop, done)` unconditionally right after building
the same `stop` func it already derives from `signal.NotifyContext` — a
no-op immediately returning on Unix or an interactive Windows console run,
and on a real registered service, SCM integration running in its own
goroutine alongside `agent.Run(ctx)`, not blocking it. An SCM Stop/Shutdown
request calls that same `stop` func — identical shutdown logic to an
interactive Ctrl+C or `SIGTERM`, not a second path to keep in sync — and
waits for `done` (closed by `main.go` once `agent.Run` actually returns)
before reporting the service `Stopped`, so the SCM can't consider the
service down, and isn't free to kill it, while cleanup is still running.

`install-spoke.ps1` registers the service running as `LocalSystem` by
default — the simplest option, but a materially higher-privilege default
than the Linux install's dedicated, unprivileged `acme-spoke` user plus one
narrowly scoped sudoers rule (above). `LocalSystem` can do essentially
anything on the box, not just what `reload_hook` needs; an operator wanting
the tighter equivalent should register the service under its own virtual
service account (`NT SERVICE\acme-spoke`) and grant that account only what
`reload_hook` actually requires instead — a per-deployment decision the
install script deliberately doesn't make for you, the same way
`acme-spoke.sudoers.example` is provided rather than force-installed on
Linux.

## Database-backed desired state

Which spokes exist, their bearer tokens, their certificate/DNS-provider
assignments, and DNS provider configs (credentials included) live in the
hub's own SQLite database (`internal/hubstore`), not `config.yaml` —
moved there so a write-capable web admin UI (and CLI tools:
`cmd/acme-onboard`, `acme-hub --generate-token`) can create/edit/delete
them directly, taking effect on the very next reload instead of requiring
a hand-edited config file. `config.yaml` keeps exactly the fields already
established as startup-only/restart-only before this change —
`listen_addr`, `data_dir`, `db_path`, TLS paths, `status_token`, hooks,
timeouts, `acme_defaults` — the same set "Config hot-reload" below has
always excluded from hot-reload, which turns out to be exactly the
YAML/database split this needed. A `config.yaml` that still has a
`spokes:` or `dns_providers:` key is a load-time error pointing at
`acme-hub --import-config`, a one-shot migration command for a file
written before this change — not silently ignored.

New `hubstore` tables: `spokes`, `spoke_tokens` (its own primary key is
what gives "a bearer token must be globally unique across every spoke"
for free, replacing the app-level check `config.HubConfig.validate()`
used to make across a whole YAML document at once), `spoke_certs`
(domains and any `domain_dns_providers` override stored as JSON columns,
reusing `config.SpokeCertConfig` directly rather than inventing a new
relational shape for data nothing ever queries by substructure), and
`dns_providers` (the full `config.DNSProviderConfig`, JSON-marshaled,
credentials included). No SQL foreign keys, matching this schema's
existing precedent (`spoke_cert_state` has none either); referential
integrity (a cert's `dns_provider` must exist, a provider can't be
removed while referenced) is enforced in Go, transactionally, by
`internal/hubstore`'s own methods — `UpsertSpokeCert` in particular also
runs `config.ValidateCertName`/`ValidateDomain` itself, not just leaving
that to callers, since `ValidateCertName`'s path-traversal guard used to
only ever run at YAML-load time; once writes go straight to the database
there's no load-time safety net left downstream to catch it if a caller
forgot.

**DNS provider credentials in the database are no less protected than
the `${VAR}`-indirected `acme-hub.env` file they replaced.** The SQLite
file is created by the hub process itself at first boot, under whatever
`DynamicUser` UID that particular boot got — no cross-boot ownership
mismatch, unlike `acme-hub.env` (a static, pre-existing file that needs
the `SupplementaryGroups` grant described below precisely because
successive boots get different UIDs). Storing credentials as cleartext
JSON in the database needs no new systemd grant and is at least as
tight as the model it replaced.

## Config hot-reload

Sending the hub process `SIGHUP` (`kill -HUP $(pidof acme-hub)`, or
`systemctl reload acme-hub`) rebuilds the hub's desired state and swaps
it in live — no restart, no dropped connections, no in-flight request
affected.

Only two things actually change this way: `spokes` and `dns_providers`
(and everything derived from them — the token→spoke index, the
`challenge.Provider` built per DNS provider) — read from the hub's
**database** (`internal/hubstore`), not `config.yaml`, since the
database-backed-desired-state cutover (see "Database-backed desired
state" below). That's a deliberate, narrow scope, not a partial
implementation of "reload everything": `listen_addr`, `tls_cert_file`/
`tls_key_file`, `data_dir`, `db_path`, and `status_token` are all
resources already bound at process start (a listening socket, an open
database file) or deliberately excluded from the hot-reloadable set —
`internal/hubapi` never reads any of the former at all, only
`cmd/acme-hub` does, once, before the `Server` is even constructed — so
there's nothing for a reload to meaningfully change there short of a
real restart.

Internally, `hubapi.Server` bundles its config, spoke desired state,
token index, and DNS provider map into one `hubState` struct held behind
an `atomic.Pointer` — every request handler loads it once per request and
reads through that snapshot, so a reload landing mid-request can never
leave a handler looking at, say, this reload's token index paired with a
different reload's spoke list (the actual bug class this design rules
out by construction, verified under `-race` with concurrent readers
hammering the server while a genuinely changing desired state reloads in
a loop). `Server.Reload`/`buildState` rebuild the whole `hubState` from
the database and only swap it in if that succeeds — a bad reload (e.g. a
stored DNS provider config with an unbuildable type) is logged and the
prior state keeps serving untouched, never partially applied.

**Two kinds of writer, one signal.** A write from the hub's own web admin
UI (see "Web admin UI" below) runs **in-process** — its handler calls
`Server.Reload` itself, synchronously, right after its own database
write, so a browser action is live on the very next request, no signal
involved at all. A write from a separate CLI process on the same host
(`cmd/acme-onboard`, `acme-hub --generate-token`, `--import-config`) has
no such hook into the already-running hub process — it writes straight
into the same database file, and the running hub genuinely has no way to
notice until it's told. `SIGHUP` is that "tell it" mechanism, unchanged
in every respect except what it now resyncs from: `deploy/acme-hub.service`
sets `ExecReload=/bin/kill -HUP $MAINPID` specifically so `systemctl
reload acme-hub` works at all — a plain `Type=simple` unit has no reload
behavior without one — and `cmd/acme-hub`'s `watchForReload` calls
`Server.Reload` on receipt, exactly as it always has.

`config.yaml`'s own `${VAR}` expansion (`fileEnvSource`, reading
`acme-hub.env` fresh on every `LoadHubConfig` call, including every
SIGHUP) still exists and still matters — just for a much smaller set of
fields now that spoke tokens and DNS provider credentials no longer live
there at all: `status_token` is the main remaining example. The
`DynamicUser=yes` + `SupplementaryGroups=acme-hub-secrets` grant that
lets the hub's freshly-allocated per-boot UID actually read that file
(verified empirically via real `systemd-run --property=DynamicUser=yes`
tests — denied without the group grant, allowed with it) is unchanged and
still correct; it just backs a narrower story than it used to.

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

The systemd deployment above (`deploy/`) is Linux-only, and so is the hub
— every deployment target discussed for it has been Linux, and no
Windows-specific work has gone into `cmd/acme-hub` itself. The **spoke**
is different: Windows is a genuine, tested deployment target for it, with
its own install tooling (`install-spoke.ps1` and the "Production
deployment (Windows service)" section above) and its own CI job
(`test-windows`, below) actually running the test suite on a real
`windows-latest` runner — not just proving the code compiles. macOS builds
remain compile-only: nothing about that platform has been verified beyond
`go build` succeeding, and there's no install tooling for it.

**Intel Mac (`darwin/amd64`) is explicitly deprioritized**, not actively
verified: Apple has ended (or announced ending) Intel support, so it's not
worth spending CI time or attention keeping this compiling as the codebase
evolves. It's still plain Go with no known reason it wouldn't build — the
command above should keep working — it's just not something a future
change is guaranteed to preserve, and it's not in CI's `cross-compile`
matrix below. Apple Silicon (`darwin/arm64`) is the macOS target that's
actually kept working.

Three platform gaps already closed, and one real gap still open:

- **`internal/hook` runs the OS-native shell, not a hardcoded `sh`.** A
  Windows install has no `sh` at all, so `reload_hook`/`notify_hook` used to
  be silently non-functional there. `hook_unix.go`/`hook_windows.go` (a
  `//go:build` split, same shape as `internal/umask` below) pick `sh -c` on
  Unix and `cmd.exe /C` on Windows — an operator's hook command needs to use
  that platform's own shell syntax (`%VAR%` not `$VAR`, on Windows).
- **No process umask on Windows, so every secret-bearing path this
  codebase writes now sets its own Windows ACL explicitly.**
  `internal/umask` still restricts the process umask to `0077` before
  either binary creates any files, Unix-only (`syscall.Umask` isn't defined
  on Windows, and file access is governed by ACLs inherited from the parent
  directory instead — `umask_windows.go` stays a documented no-op for that
  reason). What's new is `internal/secureperm.Protect`, called right
  alongside every `os.Chmod` that already exists at a path holding a
  private key, a bearer token, or the SQLite database (`internal/certwriter`,
  `internal/selfsigned`, `internal/store`, `internal/hubstore`, both
  binaries' `DataDir` setup): a no-op on Unix (the existing `os.Chmod`
  already does the real work there), and on Windows a DACL restricting the
  path to the current user and `SYSTEM` only, replacing whatever it
  inherited from its parent. Deliberately *not* applied to `cert.pem`/
  `fullchain.pem` — those stay world-readable by design (0644 on Unix) so a
  reload target running as any user can read the public half; applying the
  same restriction there would be a functional regression, not an extra
  precaution. The DACL-setting mechanism itself is confirmed working
  against a real `windows-latest` CI run (`internal/secureperm`'s tests
  read the applied DACL back via `GetNamedSecurityInfo` and check its ACE
  count). What that run does *not* cover: whether a reload target actually
  running as a *different* account than the spoke can still traverse into
  a Protect()-restricted directory to reach the world-readable files
  inside it — that needs a second real account in the test environment,
  which this CI job doesn't set up.
- **No `os.Symlink` on Windows for `internal/certwriter`'s atomic "current"
  swap.** Creating a symlink needs the same elevated privilege as above;
  `certwriter_unix.go`/`certwriter_windows.go` split `swapCurrent`
  accordingly. Windows can't atomically replace one directory with another
  via rename the way a symlink can be re-pointed, so `current` is instead
  created once as a persistent directory and retargeted in place as an
  NTFS junction (a mount-point reparse point, which — unlike a symlink —
  doesn't require `SeCreateSymbolicLinkPrivilege`) each time `Write` runs:
  clear whatever reparse data it currently holds, then set the new target.
  A crash between those two steps leaves `current` as a plain, empty
  directory rather than a torn mix of old and new files — safe, just not
  quite the single-syscall guarantee a symlink rename gives on Unix. The
  reparse-point byte layout is hand-built (`golang.org/x/sys/windows`
  doesn't export the mount-point buffer type) and confirmed working
  end-to-end against a real `windows-latest` run — which is also where two
  genuine bugs surfaced and got fixed before this landed: `fsyncDir`
  (unrelated to the junction work, but only ever exercised on Unix before)
  called `Sync()` on a directory handle, which Windows rejects outright
  ("Access is denied" — now a documented no-op there, since NTFS's own
  metadata journaling doesn't need the explicit call POSIX does); and
  `golang.org/x/sys/windows`'s own `Readlink` tripped `checkptr` fatally
  under `-race` via an internal unsafe-pointer cast, worked around by
  reading the junction back with `encoding/binary` instead of that
  library function. Exactly the kind of thing a cross-compile-only check
  would never have caught.
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
`darwin/arm64` on every push/PR — a `go build` check only, no test run —
specifically so a future platform-incompatible call (like `syscall.Umask`
was before `internal/umask` existed) fails CI immediately instead of only
surfacing the next time someone happens to try a cross-compile by hand.
`darwin/amd64` is deliberately not in this matrix, per the Intel Mac note
above. For Windows specifically, CI goes further: the separate
`test-windows` job runs on a real `windows-latest` runner (not a
cross-compile from Linux) and actually executes `go test`/`go test -race`
— scoped to the packages "genuine Windows spoke support" touched
(`internal/hook`, `internal/secureperm`, `internal/certwriter`,
`internal/store`, `internal/winservice`, `cmd/acme-spoke`), not a full
`./...`, since `cmd/acme-hub`'s own test suite has a pre-existing
Unix-only assumption (`syscall.Kill` in `main_test.go`) that's out of
scope here — the hub was never a Windows deployment target to begin with.
There's still no macOS runner in CI at all; that platform's `go build`
check in `cross-compile` is the only verification it gets.

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
mirrors this same validation for a cert written directly into the
database.

## Spoke enrollment

A lower-friction alternative to fully manual onboarding (below): `acme-hub
--generate-token` mints a one-time enrollment token for a brand-new spoke;
`acme-spoke --load-token` is the entire spoke-side setup in one command —
dialing the hub, verifying it cryptographically, and writing a working
`config.yaml` itself.

### `acme-hub --generate-token`

```
acme-hub --config /etc/acme-hub/config.yaml --generate-token \
  --spoke-id radius-spoke --cert-name radius-cert \
  --domains radius.example.com --dns-provider route53_main
```

Validates the request (same checks `acme-onboard` already applies — the
DNS provider must exist, the spoke must not already exist; this is
new-spoke enrollment only, not adding a certificate to one that's already
configured), writes the new spoke, its bearer token, and its one
certificate directly into the hub's database, and prints the one opaque
enrollment token string for the new spoke to use with
`acme-spoke --load-token`.

`--hub-url` defaults to `https://<tls_host or listen_addr host>:<listen_addr port>`
if not given explicitly. `--domain-dns-providers` accepts the same
`domain=provider,domain=provider` overrides as the mixed-DNS-providers
feature above, for a cert whose domains span more than one backend even
at enrollment time. `--token-ttl` (default `1h`) bounds how long the
printed token stays redeemable — generating one and never using it just
means it silently expires, nothing to clean up by hand.

### `POST /v1/enroll`

The hub-side endpoint `--generate-token`'s printed token is redeemed
against — the piece `--load-token` will call once it exists. Redeems a
one-time enrollment secret and hands back a brand-new spoke's real bearer
token plus the certs/domains it's authorized for — the one place in this
API a request needs no bearer token at all, since a spoke that hasn't
enrolled yet has nothing to present. Secrets are tracked in a new
`enrollment_tokens` table (schema version 4): `secret` (cleartext,
matching how bearer tokens in `config.yaml` are handled — see
`internal/hubapi/auth.go`'s `authorize` doc comment for why that's this
project's deliberate pattern, not an oversight), `spoke_id`, the
pre-generated `bearer_token` to hand back, `expires_at`, and `redeemed_at`
— deliberately no cert/domain/DNS-provider assignment duplicated here;
that already lives in the hub's database (see "Database-backed desired
state" above), and reading it live at redemption time (via the
hot-reloaded `hubState.spokes`, not a second query per request — see
"Config hot-reload") is what guarantees it can never drift stale against
a second copy.

Redemption is atomic and genuinely single-use — `hubstore.Store.RedeemEnrollmentToken`
follows the exact WHERE-guarded pattern `Claim` established for the
renewal lease, proven under real concurrent goroutines the same way. One
sequencing detail matters for correctness: the handler checks whether the
secret's associated spoke is actually present in the hub's *current*
desired state *before* consuming the secret. If the hub hasn't yet
reloaded to pick up the newly created spoke, the endpoint returns `503`
without redeeming anything — the same secret works once it has, rather
than being permanently burned by an early, doomed-to-fail attempt. In
practice this window is small: `--generate-token` writes the spoke to the
database itself, and the operator (or `acme-onboard`) just needs to send
one `SIGHUP` — or, if the spoke was created via the web admin UI instead,
there's no window at all, since that write already triggers its own
in-process reload.

## Onboarding a spoke

`cmd/acme-onboard` is a scriptable, non-interactive alternative to the
hub's web admin UI (see "Web admin UI" below) — the same same-host,
direct-database-access operational model `acme-hub --generate-token`
uses, for adding a spoke or a certificate from a script instead of a
browser.

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

`--hub-config` is read-only, used only to locate the hub's database
(`db_path`) — nothing under `spokes:`/`dns_providers:` on that file is
consulted or written. The spoke, its bearer token, and its certificate
assignment are written directly into the database (validated the same
way: the DNS provider must exist, cert names/domains must be well-formed
and path-safe), and the new spoke's complete `config.yaml` is written to
`--spoke-config-out` — one freshly generated 256-bit token
(`crypto/rand`) shared by both, so the two can't drift. It also reminds
you to copy the hub's certificate to `--hub-tls-cert-file` on the new
spoke and verify its fingerprint (see "TLS" above) — that step still has
to happen out-of-band, since the tool has no access to the spoke's
filesystem. Running it again with an existing `--spoke-id` and a new
`--cert-name` adds a second certificate to that spoke and reuses its
existing token instead of generating (and thereby invalidating) a new
one.

Validated in `internal/onboard`'s tests by writing the generated spoke
config to a file and loading it through the real `config.LoadSpokeConfig`
— not just checking the YAML looks right — and, during development, by
running the actual built binary against a real database that started with
zero spokes, copying its generated config.yaml to a real spoke host, and
completing a real issuance against Let's Encrypt staging with it.

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

### Hook status visibility

`spoke_cert_state` also carries `last_hook_at`/`last_hook_error` (schema
version 6), mirroring `internal/store.CertState`'s identically-shaped
columns on the spoke side. Before these existed, a `reload_hook`'s outcome
was recorded *only* in the spoke's own local database — the hub had no
concept of reload hooks at all, so a hook silently failing on every single
renewal left the certificate showing `"active"` here, on the admin
dashboard, and on `GET /v1/status`, indefinitely. There was no way to tell
"renewed and the consuming service actually picked it up" from "renewed,
but the service never reloaded" without logging into that specific spoke.

`hubstore.Store.MarkHookResult(spokeID, name, hookErr)` records this,
deliberately independent of `CheckinActive`/`CheckinFailed` — a hook
failure must never be conflated with (or override) a renewal failure, the
same reasoning that already separates certificate fields from
failure-streak fields in those two methods. `checkinRequest` carries three
optional fields for this — `hook_status` (`"ok"`/`"failed"`), `hook_error`,
`hook_at` — populated only when a checkin is actually reporting a hook
result (most aren't: a cert with no `reload_hook` configured never has one
to report, and the checkin reporting a fresh issuance doesn't either — see
"Certificate installation" above and `spokeagent.reportHookResult`, a
second, separate checkin sent once the hook has actually finished running,
so a slow hook never delays the hub learning about a successful renewal).
`adminEntries` (shared by `GET /v1/status` and the HTML dashboard, so
both surfaces get this for free) exposes it as `last_hook_at`/
`last_hook_error`; the dashboard renders a `Hook` column, highlighted
the same way a failed certificate status already is.

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
certificate that's configured (`state.spokes[*].Certs`, sourced from the
database — see "Database-backed desired state" above) but has never once
checked in still appears, as `status: "unknown"` (`spoke_cert_state`'s own
default), rather than silently missing from the response just because no
row exists for it yet.

A server-rendered HTML view of this same data — for a human opening a
browser rather than a monitoring tool — is available at `GET /admin`; see
"Web admin UI" below.

## Web admin UI

`GET /admin` serves a server-rendered HTML page combining the same
fleet-wide certificate data `GET /v1/status` reports as JSON (both
handlers share `internal/hubapi.adminEntries`, so the two views can never
structurally diverge on what counts as "configured" or "unknown") with
full write access to desired state: create/delete a spoke, rotate its
tokens, add/edit/remove its certificates, and create/update/remove DNS
providers — the actual point of moving desired state into the database
(see "Database-backed desired state" above).

Gated by the same `status_token` as `/v1/status` (registered in the same
`Handler()` conditional, so leaving `status_token` unset disables every
`/admin` route identically — 404, not 401, when unconfigured), but
presented differently: `/admin` uses HTTP Basic Auth
(`internal/hubapi.authorizeAdmin`) rather than a bearer header, since a
browser needs a native credential prompt to open the page directly —
a failed attempt sets `WWW-Authenticate: Basic realm="acme-hub admin"`,
which is what actually triggers that prompt. The username field is
ignored; `status_token` is the password. Basic Auth over a login-form/
session-cookie was a deliberate choice, not just the simplest option:
browsers resend cached Basic Auth credentials automatically on every
subsequent same-origin request, including `POST`s — the property that
let the write endpoints reuse this exact auth mechanism without any new
session infrastructure when they were added.

The dashboard is plain HTML rendered via Go's `html/template` (not
`text/template` — load-bearing, since it auto-escapes fields that can
carry spoke-reported text, like a checkin's error string) from inline
template constants in `internal/hubapi/admin.go`. Every write is a plain
HTML form `POST` — no client-side fetch, so nothing but the browser's own
cached Basic Auth credential is ever involved in a write; the dashboard
itself still re-fetches via `<meta http-equiv="refresh">` rather than
polling. A few destructive actions (remove a spoke/token/provider) use a
plain inline `onclick="confirm(...)"` as a safety prompt — it never
touches auth or the network, only whether the browser's normal form
submission proceeds, and degrades harmlessly (submits unconfirmed) with
JS disabled.

**CSRF defense: `Origin` header validation**
(`internal/hubapi.requireSameOrigin`). Every `POST /admin/...` request
must carry an `Origin` header whose host matches `r.Host` (what the
browser actually dialed) — missing or mismatched is rejected outright.
No session, no signed per-form token: a cross-origin page has no way to
forge this header to match, since the browser itself sets it based on
the page that initiated the request, not anything script-controlled.
This is the same "lightest mechanism that actually closes the real gap"
judgment `authorize`'s own doc comment makes for per-spoke tokens (a map
lookup, not a constant-time-compare loop) — a signed-token scheme would
need session state this design has deliberately avoided everywhere else.

**Write endpoints** (`internal/hubapi/admin_write.go`), all under the
same `/admin` prefix and `authorizeAdmin`/`requireSameOrigin` guard
(`Server.adminWriteGuard`): `POST /admin/spokes` (create — the one
endpoint that doesn't redirect to `/admin`, since the freshly generated
token is only ever shown once, on a dedicated confirmation page — see
`renderAdminNewTokenPage`), `POST /admin/spokes/{id}/delete`,
`POST /admin/spokes/{id}/tokens` (add — rotation step 1, same one-time
token page), `POST /admin/spokes/{id}/tokens/delete` (remove — rotation
step 2, refused by the store if it's the spoke's last token),
`POST /admin/spokes/{id}/certs` (upsert — the same endpoint doubles as
create and edit), `POST /admin/spokes/{id}/certs/{name}/delete`,
`POST /admin/dns-providers` (create/update — the form posts every
possible per-type field regardless of which type is selected; unused
ones for a given type are simply ignored), and
`POST /admin/dns-providers/{name}/delete`. Every handler calls
`Server.Reload` itself, synchronously, immediately after its own store
write — a browser action is live on the very next request, no `SIGHUP`
involved (see "Config hot-reload" above on why that's specifically true
for this in-process writer and not for a separate CLI process).

Whether `status_token`/`StatusToken` should eventually be renamed (e.g.
`admin_token`) now that it grants mutation, not just read access, remains
an open, low-priority question — deferred, not resolved here.

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
above) merged against `state.spokes`, and flags a certificate stale if
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

The workflow, using `internal/onboard`'s `PlanRotation` (`cmd/acme-onboard`
or the hub's web admin UI):

1. Run the rotation plan for the spoke. It generates a fresh,
   cryptographically random token and writes it directly into the hub's
   database *alongside* the spoke's existing token(s) — it deliberately
   never touches or even displays the spoke's *existing* token, only ever
   adds the new one.
2. Reload the hub (`SIGHUP` — no restart needed) — both tokens are now
   valid.
3. Update the spoke's own `hub_token` to the new value, restart the
   spoke, confirm it's actually working (a successful `/due` poll is
   enough).
4. Remove the spoke's old token (`hubstore.Store.RemoveSpokeToken` —
   refused if it would leave the spoke with zero tokens; not yet exposed
   via any CLI, only reachable directly against the store today) and
   reload again to complete the rotation — only the new token
   authenticates from this point on.

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
  either one, not just the first, and the web admin UI's write endpoints
  including that a spoke created via `POST /admin/spokes` authorizes on
  its very next request with no explicit reload (the actual point of
  the in-process `Server.Reload` call every write handler makes),
  the `Origin`-header CSRF check rejecting a missing or mismatched
  origin, and a DNS provider removal being refused while a cert still
  references it, surfaced as a real `409`, not a `500` — all via real HTTP
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
  just assumed from the SQL), the `schema_meta` migration path against
  hand-built pre-migration databases at each version, and — since
  desired state moved here — `CreateSpoke`'s duplicate-token rejection
  under real concurrent goroutines racing for the same token string,
  `DeleteSpoke`'s cascade across tokens/certs/observed state/enrollment
  tokens, `RemoveSpokeToken`'s last-token refusal, and
  `RemoveDNSProvider`'s refusal while still referenced either as a cert's
  default provider or a `domain_dns_providers` override),
  **`internal/spokeagent`** (backoff math, cert-time parsing, the local
  backoff-skip decision via a fake hub over `httptest`), **`internal/onboard`**
  (including a round-trip through the real config loader, and
  `PlanRotation` — a fresh token added to the store, distinct from and
  without disturbing the spoke's existing one(s)), **`internal/hubclient`**
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
- **Route53 credentials, and per-entry override.** By default,
  `internal/dnsprovider.New`'s `"route53"` case passes no credentials of its
  own; `route53.NewDNSProviderConfig` resolves them via the AWS SDK's own
  default chain (environment, `~/.aws/credentials`, or an IAM role) — the
  recommended default and the only option needed for a single-AWS-account
  deployment, per AWS's own guidance against long-lived keys in application
  config. Since that resolution happens once per process, it's shared by
  every `route53_*` entry that doesn't override it. For Route53 zones split
  across AWS accounts that can't be unified under one IAM principal (one
  account with multiple zones, scoped via one policy across several
  hosted-zone ARNs, doesn't need this), each `route53_*` entry may set its
  own `access_key_id`/`secret_access_key` (must be set together, or not at
  all) and optional `session_token` (temporary/STS credentials only, requires
  the other two) — settable via the web admin UI's DNS provider form (see
  "Web admin UI" above) or `hubstore.Store.UpsertDNSProvider` directly.
  `internal/dnsprovider`
  doesn't duplicate lego's own validation of these; `route53.NewDNSProviderConfig`
  already rejects an incomplete combination. Every other provider
  (Cloudflare, GoDaddy, PowerDNS, rfc2136) already takes its credentials
  directly from its own named config entry, independent of the process
  environment, so multiple distinct credential sets for those providers
  work without any of this.
- **CA flexibility (`directory_url`, `ca_cert_file`, EAB — see "ACME CA
  flexibility" above) is only partly exercised end-to-end.** EAB
  (`RegisterWithExternalAccountBinding`, `config.ACMEConfig.EABKeyID`/
  `EABHMACKey`) now has real coverage: `internal/acmeclient`'s
  `TestPebble_EABRegistration` runs pebble itself with
  `externalAccountBindingRequired` set and its own fixed test MAC keys
  (real values from pebble's own
  `test/config/pebble-config-external-account-bindings.json`, not
  invented here), proving a real registration succeeds with a valid EAB
  and — the actual enforcement check, not just a happy-path pass — that
  the same request without one is rejected. `directory_url`/`ca_cert_file`
  (pointing at a genuinely different CA, not just a different directory
  URL for the same server) remain unverified: pebble only ever presents
  one directory of its own, so this needs a second real ACME server (or a
  real non-Let's-Encrypt CA) to close, and every live test in this
  project's history besides the new EAB one has used Let's Encrypt
  staging or pebble.
- **TODO: the spoke doesn't discover certificates that already exist on a
  host.** Every cert a spoke manages today has to be requested fresh
  through this project's own ACME flow from scratch — there's no path for
  a spoke being installed onto a server that already has a live
  certificate (from `certbot`, a manual install, or a prior non-acme-agent
  tool) to detect it, adopt its existing install location, and start
  managing its renewal without first replacing it with a brand-new
  issuance. Worth doing at some point since it's a real onboarding
  friction point (a cutover forces a cert swap on day one, on every
  pre-existing host, whether or not the operator wanted one yet), but
  it's a genuinely new capability, not a bug fix — it needs its own design
  pass (how "discover" would even work: scan well-known paths? read
  existing web-server/service config? require the operator to point at a
  specific file?) before any implementation starts. Not scoped or planned
  yet - recorded here so it isn't lost.
