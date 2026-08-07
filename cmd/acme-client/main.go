// Command acme-client is the spoke agent: it generates its own key, drives
// its own ACME order, installs the resulting certificate locally, and runs
// its own local reload hook. It polls the hub for renewal instructions and
// relays DNS-01 challenges through it, but never sends the hub a private
// key or DNS provider credential — those never leave this host (or, for
// DNS credentials, never arrive on it at all).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"acme-agent/config"
	"acme-agent/internal/hubclient"
	"acme-agent/internal/spokeagent"
	"acme-agent/internal/store"
)

func main() {
	if err := run(); err != nil {
		slog.Error("acme-client exiting", "error", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "./config.yaml", "path to this spoke's config.yaml")
	once := flag.Bool("once", false, "run a single pass over all certificates, then exit (default: run as a daemon)")
	flag.Parse()

	syscall.Umask(0o077)

	cfg, err := config.LoadSpokeConfig(*configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return fmt.Errorf("create data_dir: %w", err)
	}
	if err := os.Chmod(cfg.DataDir, 0o750); err != nil { // MkdirAll's mode is subject to umask; chmod explicitly
		return fmt.Errorf("chmod data_dir: %w", err)
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	hub, err := hubclient.New(cfg.HubURL, cfg.HubToken, cfg.HubTLSCertFile)
	if err != nil {
		return fmt.Errorf("build hub client: %w", err)
	}
	agent := spokeagent.New(cfg, st, hub)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *once {
		agent.RunOnce(ctx)
		return nil
	}

	agent.Run(ctx)
	return nil
}
