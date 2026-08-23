// Command acme-hub is the centralized renewal authority: it tracks what
// certificates spokes have, decides when they're due, and relays DNS-01
// challenges (holding DNS provider credentials so spokes never need them).
// It never holds a private key or a signed certificate — spokes generate
// and install those themselves.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/tmhal5l13/acme-agent/config"
	"github.com/tmhal5l13/acme-agent/internal/hubapi"
	"github.com/tmhal5l13/acme-agent/internal/hubstore"
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
	flag.Parse()

	umask.Restrict()

	cfg, err := config.LoadHubConfig(*configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
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

	go watchForReload(ctx, *configPath, server)

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

// watchForReload re-reads configPath and applies it to server on every
// SIGHUP, until ctx is cancelled. This is a separate signal.Notify loop
// rather than reusing run's signal.NotifyContext for interrupt/SIGTERM:
// NotifyContext cancels a context once and is done, which is exactly
// wrong for a signal meant to be handled repeatedly for the life of the
// process (the standard reload-on-SIGHUP pattern many daemons use, e.g.
// nginx). A failed reload (bad YAML, a cert referencing an unknown
// dns_provider, ...) is logged and otherwise ignored - see
// hubapi.Server.Reload's doc comment for why it never partially applies
// a bad config, only cleanly rejects it. Only config.HubConfig fields
// hubapi.Server actually reads (spokes, dns_providers) take effect this
// way; listen_addr, TLS cert paths, data_dir, and db_path still need a
// real restart - see ARCHITECTURE.md "Config hot-reload".
func watchForReload(ctx context.Context, configPath string, server *hubapi.Server) {
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	defer signal.Stop(sighup)

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

	fingerprint, err := certFingerprint(cfg.TLSCertFile)
	if err != nil {
		return fmt.Errorf("read certificate fingerprint: %w", err)
	}
	slog.Info("hub TLS certificate ready", "sha256_fingerprint", fingerprint, "cert_file", cfg.TLSCertFile)

	return nil
}

func certFingerprint(certPath string) (string, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", fmt.Errorf("no PEM block found in %s", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:]), nil
}
