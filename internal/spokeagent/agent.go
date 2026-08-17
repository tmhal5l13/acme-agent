// Package spokeagent drives a spoke's polling loop: ask the hub whether
// each configured certificate is due, and if so, run the full issue/renew
// pipeline — ACME order, DNS-01 relayed through the hub, install locally,
// reload hook, report the outcome back to the hub.
package spokeagent

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math"
	"path/filepath"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"

	"github.com/tmhal5l13/acme-agent/config"
	"github.com/tmhal5l13/acme-agent/internal/acmeclient"
	"github.com/tmhal5l13/acme-agent/internal/certwriter"
	"github.com/tmhal5l13/acme-agent/internal/hook"
	"github.com/tmhal5l13/acme-agent/internal/hubclient"
	"github.com/tmhal5l13/acme-agent/internal/store"
)

// Agent holds everything the polling loop needs: the spoke's own desired
// state (config), its local observed state (store — what it currently has
// installed), and its connection to the hub.
type Agent struct {
	cfg *config.SpokeConfig
	st  *store.Store
	hub *hubclient.Client
}

func New(cfg *config.SpokeConfig, st *store.Store, hub *hubclient.Client) *Agent {
	return &Agent{cfg: cfg, st: st, hub: hub}
}

// Run blocks, processing all certificates immediately and then again every
// cfg.PollInterval, until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) {
	a.RunOnce(ctx)

	ticker := time.NewTicker(a.cfg.PollInterval.Duration())
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("spoke agent stopping")
			return
		case <-ticker.C:
			a.RunOnce(ctx)
		}
	}
}

// RunOnce processes every configured certificate a single time: due ones
// (per the hub) are issued/renewed, not-due ones are skipped, failing ones
// are logged (one bad certificate must not stop the others or crash the
// process).
func (a *Agent) RunOnce(ctx context.Context) {
	for _, cert := range a.cfg.Certs {
		if err := a.processIfDue(ctx, cert); err != nil {
			slog.Error("processing certificate", "name", cert.Name, "error", err)
		}
	}
}

func (a *Agent) processIfDue(ctx context.Context, cert config.SpokeLocalCertConfig) error {
	due, err := a.checkDue(ctx, cert.Name)
	if err != nil {
		return fmt.Errorf("check due with hub: %w", err)
	}
	if !due {
		return nil
	}

	// The hub decides *whether* a cert is due (based on expiry); backoff
	// after a *failed* attempt is a local decision — the hub has no notion
	// of retry state, only of what was last successfully reported.
	cs, err := a.st.GetOrCreateCertState(cert.Name)
	if err != nil {
		return fmt.Errorf("load local state: %w", err)
	}

	if cs.Status == "failed" {
		backoff := backoffFor(cs.ConsecutiveFailures, a.cfg.RetryBackoff.Duration(), a.cfg.MaxRetryBackoff.Duration())
		if cs.LastAttemptAt.Valid && time.Since(cs.LastAttemptAt.Time) < backoff {
			slog.Debug("skipping certificate, backing off after previous failure",
				"name", cert.Name, "consecutive_failures", cs.ConsecutiveFailures, "backoff", backoff)
			return nil
		}
	}

	return a.ProcessCert(ctx, cert)
}

// checkDue asks the hub whether certName is due, bounded by the
// general-purpose request timeout — unlike a dns01 present/cleanup relay
// call, this never blocks on a slow DNS provider.
func (a *Agent) checkDue(ctx context.Context, certName string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, a.cfg.RequestTimeout.Duration())
	defer cancel()
	return a.hub.Due(ctx, certName)
}

// checkin reports req to the hub for certName, bounded the same way.
func (a *Agent) checkin(ctx context.Context, certName string, req hubclient.CheckinRequest) error {
	ctx, cancel := context.WithTimeout(ctx, a.cfg.RequestTimeout.Duration())
	defer cancel()
	return a.hub.Checkin(ctx, certName, req)
}

// backoffFor computes exponential backoff (retryBackoff * 2^(failures-1)),
// capped at max — the same formula the original single-host scheduler
// used, now applied locally by each spoke instead of centrally.
func backoffFor(consecutiveFailures int, retryBackoff, max time.Duration) time.Duration {
	backoff := time.Duration(float64(retryBackoff) * math.Pow(2, float64(consecutiveFailures-1)))
	if backoff > max {
		return max
	}
	return backoff
}

// ProcessCert runs the full issue/renew pipeline for one certificate
// unconditionally, ignoring due/backoff.
func (a *Agent) ProcessCert(ctx context.Context, cert config.SpokeLocalCertConfig) error {
	dirURL, err := acmeclient.DirectoryURL(a.cfg.ACME.Environment)
	if err != nil {
		return a.fail(ctx, cert, err)
	}

	user, err := acmeclient.GetOrRegisterAccount(a.st, dirURL, a.cfg.ACME.Email)
	if err != nil {
		return a.fail(ctx, cert, fmt.Errorf("get account: %w", err))
	}

	provider := &hubclient.DNS01Provider{Client: a.hub, CertName: cert.Name, Timeout: a.cfg.DNS01Timeout.Duration()}

	var challengeOpts []dns01.ChallengeOption
	if a.cfg.SkipPropagationCheck {
		challengeOpts = append(challengeOpts, dns01.DisableCompletePropagationRequirement())
	}

	certResource, err := acmeclient.Issue(user, dirURL, provider, cert.Domains, challengeOpts...)
	if err != nil {
		return a.fail(ctx, cert, fmt.Errorf("issue certificate: %w", err))
	}

	certDir := filepath.Join(a.cfg.DataDir, "certs", cert.Name)
	if err := certwriter.Write(certDir, certResource.PrivateKey, certResource.Certificate, certResource.IssuerCertificate); err != nil {
		return a.fail(ctx, cert, fmt.Errorf("write certificate: %w", err))
	}

	notBefore, notAfter, serial, err := parseCertTimes(certResource.Certificate)
	if err != nil {
		return a.fail(ctx, cert, fmt.Errorf("parse issued certificate: %w", err))
	}

	if err := a.st.MarkIssued(cert.Name, notBefore, notAfter, serial); err != nil {
		return fmt.Errorf("record issuance locally: %w", err)
	}

	if err := a.checkin(ctx, cert.Name, hubclient.CheckinRequest{
		Domains: cert.Domains, NotBefore: notBefore, NotAfter: notAfter, Serial: serial, Status: "active",
	}); err != nil {
		// Local state is already correct regardless; a failed checkin just
		// means the hub's view stays stale until the next successful one.
		slog.Error("report checkin to hub", "name", cert.Name, "error", err)
	}

	slog.Info("issued certificate", "name", cert.Name, "domains", cert.Domains, "not_after", notAfter, "dir", certDir)

	// Hook failure is intentionally not treated as a certificate failure —
	// see internal/hook for why. Its outcome is recorded separately, and
	// purely locally (the hub has no notion of reload hooks at all).
	hookErr := hook.Run(ctx, cert.ReloadHook, a.cfg.HookTimeout.Duration())
	if err := a.st.MarkHookResult(cert.Name, hookErr); err != nil {
		slog.Error("record hook result", "name", cert.Name, "error", err)
	}

	return nil
}

func (a *Agent) fail(ctx context.Context, cert config.SpokeLocalCertConfig, attemptErr error) error {
	if markErr := a.st.MarkFailed(cert.Name, attemptErr); markErr != nil {
		slog.Error("record failure locally", "name", cert.Name, "error", markErr)
	}
	if checkinErr := a.checkin(ctx, cert.Name, hubclient.CheckinRequest{
		Domains: cert.Domains, Status: "failed", Error: attemptErr.Error(),
	}); checkinErr != nil {
		slog.Error("report failure to hub", "name", cert.Name, "error", checkinErr)
	}
	return attemptErr
}

func parseCertTimes(certPEM []byte) (notBefore, notAfter time.Time, serial string, err error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, time.Time{}, "", fmt.Errorf("no PEM block found in issued certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, time.Time{}, "", fmt.Errorf("parse x509 certificate: %w", err)
	}
	return cert.NotBefore, cert.NotAfter, cert.SerialNumber.String(), nil
}
