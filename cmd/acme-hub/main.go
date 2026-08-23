// Command acme-hub is the centralized renewal authority: it tracks what
// certificates spokes have, decides when they're due, and relays DNS-01
// challenges (holding DNS provider credentials so spokes never need them).
// It never holds a private key or a signed certificate — spokes generate
// and install those themselves.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/tmhal5l13/acme-agent/config"
	"github.com/tmhal5l13/acme-agent/internal/enrolltoken"
	"github.com/tmhal5l13/acme-agent/internal/hubapi"
	"github.com/tmhal5l13/acme-agent/internal/hubstore"
	"github.com/tmhal5l13/acme-agent/internal/onboard"
	"github.com/tmhal5l13/acme-agent/internal/selfsigned"
	"github.com/tmhal5l13/acme-agent/internal/umask"
)

func main() {
	if err := run(); err != nil {
		slog.Error("acme-hub exiting", "error", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "./config.yaml", "path to the hub's config.yaml")

	generateToken := flag.Bool("generate-token", false, "generate a one-time spoke enrollment token and exit, instead of running as a daemon - see the other flags below")
	gtSpokeID := flag.String("spoke-id", "", "(-generate-token) new spoke's id")
	gtCertName := flag.String("cert-name", "", "(-generate-token) certificate name, must be unique within the spoke")
	gtDomains := flag.String("domains", "", "(-generate-token) comma-separated domains, e.g. radius.example.com or example.com,*.example.com")
	gtDNSProvider := flag.String("dns-provider", "", "(-generate-token) name of an entry already defined under dns_providers")
	gtDomainDNSProviders := flag.String("domain-dns-providers", "", "(-generate-token) optional comma-separated domain=dns_provider overrides, for domains on a different provider than -dns-provider")
	gtHubURL := flag.String("hub-url", "", "(-generate-token) URL the new spoke will dial to reach this hub; defaults to https://<tls_host or listen_addr host>:<listen_addr port>")
	gtTokenTTL := flag.Duration("token-ttl", time.Hour, "(-generate-token) how long the printed enrollment token stays valid")

	flag.Parse()

	umask.Restrict()

	cfg, err := config.LoadHubConfig(*configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if *generateToken {
		return runGenerateToken(cfg, generateTokenArgs{
			SpokeID:            *gtSpokeID,
			CertName:           *gtCertName,
			Domains:            *gtDomains,
			DNSProvider:        *gtDNSProvider,
			DomainDNSProviders: *gtDomainDNSProviders,
			HubURL:             *gtHubURL,
			TTL:                *gtTokenTTL,
		})
	}

	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return fmt.Errorf("create data_dir: %w", err)
	}
	if err := os.Chmod(cfg.DataDir, 0o750); err != nil { // MkdirAll's mode is subject to umask; chmod explicitly
		return fmt.Errorf("chmod data_dir: %w", err)
	}

	st, err := hubstore.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	server, err := hubapi.NewServer(cfg, st)
	if err != nil {
		return fmt.Errorf("build hub server: %w", err)
	}

	if err := ensureTLS(cfg); err != nil {
		return fmt.Errorf("prepare TLS certificate: %w", err)
	}

	httpServer := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: server.Handler(),
		TLSConfig: &tls.Config{
			// Both ends are always this project's own binaries (see
			// internal/hubclient.New's identical MinVersion pin) - no
			// third-party TLS 1.2-only peer needs to interoperate here.
			MinVersion: tls.VersionTLS13,
		},
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		// WriteTimeout bounds the whole request, including however long a
		// handler takes to produce a response - it must stay comfortably
		// above dnsProviderTimeout (the DNS-01 relay's own internal
		// timeout, see internal/hubapi/dns01.go), or the connection would
		// get cut before that timeout even has a chance to fire and
		// return a real error to the spoke.
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Runs alongside the HTTP server for the process lifetime, stopping
	// on the same ctx cancellation - see internal/hubapi.RunWatchdog for
	// what it's for. watchdogScanInterval is how often it looks, not how
	// stale something has to be to trip it (that's cfg.WatchdogStaleAfter,
	// operator-configurable); a fixed, fairly frequent scan cadence is
	// cheap (Store.All() against a local SQLite file) and keeps detection
	// latency well under the staleness threshold itself.
	go server.RunWatchdog(ctx, watchdogScanInterval)

	// signal.Notify is called synchronously, here, before watchForReload
	// ever runs as a goroutine - not inside it. SIGHUP's default
	// disposition (unlike SIGTERM/SIGINT) is to terminate the process
	// outright; registering it inside the goroutine would leave a real
	// window between "go watchForReload(...) is scheduled" and "its
	// signal.Notify call actually executes" during which an early SIGHUP
	// would kill acme-hub instead of triggering a reload. Registering it
	// here first closes that window completely.
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	defer signal.Stop(sighup)
	go watchForReload(ctx, sighup, *configPath, server)

	serveErr := make(chan error, 1)
	go func() {
		slog.Info("acme-hub listening", "addr", cfg.ListenAddr, "tls_cert", cfg.TLSCertFile)
		serveErr <- httpServer.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
	}()

	select {
	case err := <-serveErr:
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("serve: %w", err)
		}
	case <-ctx.Done():
		slog.Info("acme-hub stopping")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
	}

	return nil
}

// generateTokenArgs is the -generate-token flag group, gathered into one
// struct so runGenerateToken doesn't take eight separate parameters.
type generateTokenArgs struct {
	SpokeID            string
	CertName           string
	Domains            string
	DNSProvider        string
	DomainDNSProviders string
	HubURL             string
	TTL                time.Duration
}

// runGenerateToken is -generate-token's entire job: validate args against
// the hub's current config (via onboard.PlanEnrollment), mint and store a
// one-time enrollment secret, and print everything the operator needs -
// the hub-config snippet to paste (same shape acme-onboard already
// produces for a brand-new spoke), and one opaque token string to hand to
// the new spoke for `acme-spoke --load-token`. See ARCHITECTURE.md "Spoke
// enrollment" for the full workflow this is one step of.
//
// Deliberately does not touch config.yaml itself - same reasoning
// internal/onboard has always used: programmatically editing a
// hand-authored, commented YAML file risks mangling it in a way a human
// wouldn't. The operator still pastes the snippet by hand, then reloads
// the hub with SIGHUP (not a restart - see "Config hot-reload").
func runGenerateToken(cfg *config.HubConfig, args generateTokenArgs) error {
	if args.SpokeID == "" || args.CertName == "" || args.Domains == "" || args.DNSProvider == "" {
		return fmt.Errorf("-generate-token requires -spoke-id, -cert-name, -domains, and -dns-provider")
	}

	hubURL := args.HubURL
	if hubURL == "" {
		u, err := defaultHubURL(cfg)
		if err != nil {
			return fmt.Errorf("determine hub url (pass -hub-url explicitly to override): %w", err)
		}
		hubURL = u
	}

	domainDNSProviders, err := parseDomainDNSProviders(args.DomainDNSProviders)
	if err != nil {
		return fmt.Errorf("parse -domain-dns-providers: %w", err)
	}

	plan, err := onboard.PlanEnrollment(cfg, onboard.EnrollmentRequest{
		SpokeID:            args.SpokeID,
		CertName:           args.CertName,
		Domains:            strings.Split(args.Domains, ","),
		DNSProvider:        args.DNSProvider,
		DomainDNSProviders: domainDNSProviders,
		HubURL:             hubURL,
	})
	if err != nil {
		return fmt.Errorf("plan enrollment: %w", err)
	}

	// Idempotent (EnsureCert never touches an existing cert/key pair), so
	// safe to call here even if the hub daemon has never actually been
	// started yet - the fingerprint below needs a real certificate to
	// exist regardless of whether this is the hub's very first operation.
	if err := ensureTLS(cfg); err != nil {
		return fmt.Errorf("prepare TLS certificate: %w", err)
	}
	fingerprint, err := selfsigned.Fingerprint(cfg.TLSCertFile)
	if err != nil {
		return fmt.Errorf("read certificate fingerprint: %w", err)
	}

	st, err := hubstore.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()
	if err := st.InsertEnrollmentToken(plan.EnrollmentSecret, args.SpokeID, plan.BearerToken, time.Now().Add(args.TTL)); err != nil {
		return fmt.Errorf("insert enrollment token: %w", err)
	}

	token, err := enrolltoken.Token{HubURL: hubURL, Fingerprint: fingerprint, Secret: plan.EnrollmentSecret}.Encode()
	if err != nil {
		return fmt.Errorf("encode enrollment token: %w", err)
	}

	fmt.Println("=== Add this to the hub's config.yaml under spokes: ===")
	fmt.Print(plan.HubConfigYAML)
	fmt.Println()
	fmt.Printf("=== Add to the hub's env file ===\n%s=%s\n\n", plan.HubEnvVarName, plan.BearerToken)
	fmt.Println("Then reload the hub - no restart needed:")
	fmt.Println("  systemctl reload acme-hub   # or: kill -HUP $(pidof acme-hub)")
	fmt.Println()
	fmt.Printf("On the new spoke, valid for %s:\n", args.TTL)
	fmt.Printf("  acme-spoke --load-token %s\n", token)

	return nil
}

// parseDomainDNSProviders parses -domain-dns-providers's
// "domain=provider,domain=provider" flag value.
func parseDomainDNSProviders(s string) (map[string]string, error) {
	if s == "" {
		return nil, nil
	}
	m := make(map[string]string)
	for _, pair := range strings.Split(s, ",") {
		domain, provider, ok := strings.Cut(pair, "=")
		if !ok || domain == "" || provider == "" {
			return nil, fmt.Errorf("invalid domain=dns_provider pair %q", pair)
		}
		m[domain] = provider
	}
	return m, nil
}

// defaultHubURL derives the URL a spoke would dial to reach this hub from
// cfg alone, when -hub-url isn't given explicitly - the same host
// selection ensureTLS already uses for the certificate's own SAN (real,
// dialable listen_addr host, or tls_host for a wildcard bind), paired
// with listen_addr's port.
func defaultHubURL(cfg *config.HubConfig) (string, error) {
	_, port, err := net.SplitHostPort(cfg.ListenAddr)
	if err != nil {
		return "", fmt.Errorf("parse listen_addr: %w", err)
	}
	host := cfg.TLSHost
	if host == "" {
		host, _, err = net.SplitHostPort(cfg.ListenAddr)
		if err != nil {
			return "", fmt.Errorf("parse listen_addr: %w", err)
		}
	}
	return "https://" + net.JoinHostPort(host, port), nil
}

// watchForReload re-reads configPath and applies it to server on every
// SIGHUP received on sighup, until ctx is cancelled. sighup must already be
// registered via signal.Notify by the caller, synchronously, before this
// runs as a goroutine - see run's comment on why registering it here
// instead would leave a real window where an early SIGHUP kills the
// process via its default disposition instead of triggering a reload.
//
// This is a separate signal-handling loop rather than reusing run's
// signal.NotifyContext for interrupt/SIGTERM: NotifyContext cancels a
// context once and is done, which is exactly wrong for a signal meant to
// be handled repeatedly for the life of the process (the standard
// reload-on-SIGHUP pattern many daemons use, e.g. nginx). A failed reload
// (bad YAML, a cert referencing an unknown dns_provider, ...) is logged
// and otherwise ignored - see hubapi.Server.Reload's doc comment for why
// it never partially applies a bad config, only cleanly rejects it. Only
// config.HubConfig fields hubapi.Server actually reads (spokes,
// dns_providers) take effect this way; listen_addr, TLS cert paths,
// data_dir, and db_path still need a real restart - see ARCHITECTURE.md
// "Config hot-reload".
func watchForReload(ctx context.Context, sighup <-chan os.Signal, configPath string, server *hubapi.Server) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-sighup:
			cfg, err := config.LoadHubConfig(configPath)
			if err != nil {
				slog.Error("reload: load config", "error", err)
				continue
			}
			if err := server.Reload(cfg); err != nil {
				slog.Error("reload: apply config", "error", err)
				continue
			}
			slog.Info("reloaded config", "path", configPath)
		}
	}
}

const (
	shutdownTimeout = 10 * time.Second

	// readHeaderTimeout/readTimeout bound how long a client gets to
	// actually send a complete request (headers, then body) - generous
	// for these small checkin/dns01 JSON payloads, but not unbounded, so
	// a slow-loris-style client can't hold a connection (and the
	// goroutine serving it) open indefinitely.
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 10 * time.Second
	// writeTimeout must stay comfortably above dnsProviderTimeout - see
	// the http.Server literal's comment above.
	writeTimeout = 5 * time.Minute
	idleTimeout  = 2 * time.Minute

	watchdogScanInterval = 5 * time.Minute
)

// ensureTLS makes sure cfg.TLSCertFile/TLSKeyFile exist, self-signing a
// fresh certificate on first run if not (see internal/selfsigned for why
// self-signed rather than a real CA), then logs its SHA-256 fingerprint —
// what an operator compares against when copying the certificate to a new
// spoke, the same role an SSH host key fingerprint plays.
func ensureTLS(cfg *config.HubConfig) error {
	if err := os.MkdirAll(filepath.Dir(cfg.TLSCertFile), 0o750); err != nil {
		return fmt.Errorf("create tls_cert_file directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.TLSKeyFile), 0o750); err != nil {
		return fmt.Errorf("create tls_key_file directory: %w", err)
	}

	host := cfg.TLSHost
	if host == "" {
		var err error
		host, _, err = net.SplitHostPort(cfg.ListenAddr)
		if err != nil {
			return fmt.Errorf("parse listen_addr: %w", err)
		}
	}

	if err := selfsigned.EnsureCert(cfg.TLSCertFile, cfg.TLSKeyFile, host); err != nil {
		return err
	}

	fingerprint, err := selfsigned.Fingerprint(cfg.TLSCertFile)
	if err != nil {
		return fmt.Errorf("read certificate fingerprint: %w", err)
	}
	slog.Info("hub TLS certificate ready", "sha256_fingerprint", fingerprint, "cert_file", cfg.TLSCertFile)

	return nil
}
