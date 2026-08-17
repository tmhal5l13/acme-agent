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

Working and live-tested against real, multi-host infrastructure — hub and
spokes on separate machines, real DNS-01 relay, real Let's Encrypt staging
issuance and renewal, real systemd deployment as root — but young. Before
relying on this, know what hasn't been exercised yet:

- **Four of five DNS providers are proven end-to-end**: Route53,
  Cloudflare, PowerDNS, and rfc2136 (BIND, TSIG-authenticated) have each
  driven a real DNS-01 challenge and issued a real certificate. **GoDaddy
  is currently blocked, not just untested**: `lego` (this project's ACME
  library) only supports GoDaddy's legacy `sso-key` credentials, and
  GoDaddy's modernized API requires a Bearer-token Personal Access Token
  that `lego` has no support for as of this writing — GoDaddy support
  won't work until that lands upstream.
- **Let's Encrypt production has never been used** — every test so far has
  deliberately used staging.
- **A real renewal (not just initial issuance) has been verified** — a
  certificate was forced due and actually renewed, with a genuinely new
  certificate written to disk and the hub's state updated to match.
- **Two spokes have run concurrently against one hub** without issue, but
  this wasn't a rigorous concurrency stress test.
- **Behavior at high spoke counts is unverified**, distinct from the point
  above. Two known concentration points exist by design: the hub's SQLite
  store serializes writes (every checkin is one), and every spoke's DNS-01
  challenge funnels through the hub's relay to the actual DNS provider,
  whose own API rate limits are outside this project's control. Renewal
  jitter spreads *when* certificates come due so they don't all cluster at
  once, but doesn't change either ceiling. Where the real limit is — tens
  of spokes or thousands — has never been tested. Worth noting the
  opposite is also true in one respect: each spoke owns its own ACME
  account rather than sharing one, which spreads exposure to Let's
  Encrypt's own per-account rate limits rather than concentrating it.
- **`reload_hook` has never run against a real service.** It's unit-tested
  only — no live test in this project's history has actually installed a
  certificate and reloaded something that consumes it.
- **`notify_hook` has never fired in a live run.** The transition-detection
  logic it depends on *has* been exercised for real (a genuine "failed"
  checkin occurred during development), but no hook was configured at the
  time, so the actual notification path remains unverified end-to-end.
- **No hub-side failure detection for a spoke that can't reach the hub at
  all.** `notify_hook` only fires on an explicit "failed" checkin — a spoke
  that can't reach the hub (network/firewall/DNS issue) has no way to
  report that fact, and the hub currently has no proactive staleness check
  to catch the silence. This is a real gap found during development, not a
  hypothetical one.
- **No certificate-revocation checking** (CRL or otherwise) — a revoked
  certificate would only get renewed on its normal schedule, not
  detected and replaced early.
- **The ACME CA is hardcoded to Let's Encrypt** — no configurable directory
  URL yet, so no private CA or other public ACME CA support. No External
  Account Binding (EAB) support either, which several CAs (including some
  private CA setups) require for account registration.

See `ARCHITECTURE.md`'s "Known gaps" for the full list, including exactly
which packages have automated test coverage and which have only been
verified by hand.

## How this was built

I'm not a programmer. This project was directed entirely in natural
language — architecture decisions, requirements, and scope were mine;
Claude (Anthropic's AI) wrote every line of code. I'm disclosing that
plainly rather than leaving it to be discovered, because I think it should
be a baseline expectation, not a caveat buried in a commit message.

What I'd rather you evaluate this on than the fact of AI authorship: the
project's git history is the actual record of how it was built, and it
holds up to scrutiny. Bugs were found by deploying across real,
multi-host infrastructure and watching things actually break — not
assumed away — and each one got a regression test, not just a fix (see
the `tls_host` commit for an example: a real TLS handshake failure, found
only because the hub and spokes were running on separate real hosts,
fixed with both the config change and a test proving the failure mode).
The [Status](#status) section above says plainly what hasn't been
verified yet, rather than hiding it. `govulncheck` and the race detector
have both been run against this codebase, not just `go build`.

One real limitation worth being direct about: I can't personally review
a pull request by reading its code. What I can and will do is require
that any change — mine or a contributor's — passes the existing test
suite, `go vet`, and `govulncheck`, and gets an AI-assisted review before
merging. That's a real form of review, just not one that depends on code
literacy I don't have. If that's not a review process you trust, that's a
completely reasonable reason to hold off on this project, or to review
changes yourself before pulling them into anything you run.

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
