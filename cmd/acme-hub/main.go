// Command acme-hub is the centralized renewal authority: it tracks what
// certificates spokes have, decides when they're due, and relays DNS-01
// challenges (holding DNS provider credentials so spokes never need them).
// It never holds a private key or a signed certificate — spokes generate
// and install those themselves.
package main

import (
	"context"
	"crypto/sha256"
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

	"acme-agent/config"
	"acme-agent/internal/hubapi"
	"acme-agent/internal/hubstore"
	"acme-agent/internal/selfsigned"
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

	syscall.Umask(0o077)

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
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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

const shutdownTimeout = 10 * time.Second

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

	host, _, err := net.SplitHostPort(cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("parse listen_addr: %w", err)
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
