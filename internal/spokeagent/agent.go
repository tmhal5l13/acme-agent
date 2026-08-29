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
	// Backoff after a *failed* attempt is a purely local decision — the
	// hub has no notion of retry state, only of what was last
	// successfully reported — so it's checked before ever calling the
	// hub, not after. This matters beyond just avoiding an unnecessary
	// network call: the hub's /due now also atomically claims a renewal
	// lease when it answers "due" (see internal/hubapi's handleDue and
	// hubstore.Store.Claim), released only when a checkin eventually
	// arrives. If due were checked first and backoff skipped the actual
	// attempt afterward, that claim would sit unreleased until it
	// self-expired — potentially blocking this same spoke's own next
	// poll tick from claiming it, for no reason. Checking backoff first
	// means the hub is never asked, and therefore nothing is ever
	// claimed, for an attempt that was never going to happen anyway.
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

	due, err := a.checkDue(ctx, cert.Name)
	if err != nil {
		return fmt.Errorf("check due with hub: %w", err)
	}
	if !due {
		// Not due for renewal doesn't mean nothing to do: if the last
		// reload_hook run for this cert failed, retry just the hook (not
		// the ACME flow) on every poll cycle until it succeeds - poll_interval
		// itself is the retry throttle, deliberately not a separate backoff
		// (see retryHookIfFailed's own doc comment).
		a.retryHookIfFailed(ctx, cert, cs)
		return nil
	}

	return a.ProcessCert(ctx, cert)
}

// retryHookIfFailed retries cert's reload_hook, on its own, against
// whatever's already installed - used when the certificate itself isn't
// due for renewal but its last recorded hook run failed. Without this, a
// broken reload_hook (wrong fmsadmin command, a typo, a permissions
// problem) would only ever be retried on the certificate's next natural
// renewal - weeks to months away - even though the fix might be a
// one-line config edit away right now. No separate backoff: poll_interval
// (15m by default) is already the throttle, and a broken hook is worth
// retrying every cycle until it's fixed, not worth its own schedule.
// cs is the caller's already-loaded local state, reused rather than
// re-read, since processIfDue already paid for it.
func (a *Agent) retryHookIfFailed(ctx context.Context, cert config.SpokeLocalCertConfig, cs *store.CertState) {
	if cert.ReloadHook == "" || !cs.LastHookError.Valid {
		return
	}

	hookErr := hook.Run(ctx, cert.ReloadHook, a.hookTimeoutFor(cert))
	if err := a.st.MarkHookResult(cert.Name, hookErr); err != nil {
		slog.Error("record hook retry result", "name", cert.Name, "error", err)
	}
	a.reportHookResult(ctx, cert, cs.NotBefore.Time, cs.NotAfter.Time, cs.SerialNumber.String, hookErr)
}

// hookTimeoutFor resolves cert's own hook_timeout override if set, falling
// back to the spoke-wide default - the same zero-means-default convention
// config.SpokeLocalCertConfig.HookTimeout's own doc comment describes.
func (a *Agent) hookTimeoutFor(cert config.SpokeLocalCertConfig) time.Duration {
	if cert.HookTimeout != 0 {
		return cert.HookTimeout.Duration()
	}
	return a.cfg.HookTimeout.Duration()
}

// reportHookResult tells the hub about a reload_hook's outcome via a
// second, separate checkin from the one (if any) that reported the
// certificate's own active/failed status - see hubclient.CheckinRequest's
// HookStatus field for why this is a second call rather than folded into
// the first: moving the existing post-issuance checkin to after hook.Run
// would delay the hub learning about a successful renewal by however long
// a slow hook takes, a real behavior change not worth making silently.
// notBefore/notAfter/serial are the certificate's already-known validity
// window - this call never describes a new certificate, whether it
// follows a fresh issuance (ProcessCert, using the just-issued
// certificate's own fields) or a standalone retry (retryHookIfFailed,
// using cs's already-recorded fields, since nothing about the certificate
// itself has changed). No-ops entirely if cert has no reload_hook
// configured - nothing to report. Best-effort, like every other checkin
// call in this file: a failed report just means the hub's view stays
// stale until the next one.
func (a *Agent) reportHookResult(ctx context.Context, cert config.SpokeLocalCertConfig, notBefore, notAfter time.Time, serial string, hookErr error) {
	if cert.ReloadHook == "" {
		return
	}

	req := hubclient.CheckinRequest{
		Domains: cert.Domains, Status: "active",
		NotBefore: notBefore, NotAfter: notAfter, Serial: serial,
		HookStatus: "ok", HookAt: time.Now().UTC(),
	}
	if hookErr != nil {
		req.HookStatus = "failed"
		req.HookError = hookErr.Error()
	}

	if err := a.checkin(ctx, cert.Name, req); err != nil {
		slog.Error("report hook result to hub", "name", cert.Name, "error", err)
	}
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
	dirURL, err := acmeclient.DirectoryURL(a.cfg.ACME)
	if err != nil {
		return a.fail(ctx, cert, err)
	}

	user, err := acmeclient.GetOrRegisterAccount(a.st, dirURL, a.cfg.ACME)
	if err != nil {
		return a.fail(ctx, cert, fmt.Errorf("get account: %w", err))
	}

	provider := &hubclient.DNS01Provider{Client: a.hub, CertName: cert.Name, Timeout: a.cfg.DNS01Timeout.Duration()}

	var challengeOpts []dns01.ChallengeOption
	if a.cfg.SkipPropagationCheck {
		challengeOpts = append(challengeOpts, dns01.DisableCompletePropagationRequirement())
	}

	certResource, err := acmeclient.Issue(user, dirURL, a.cfg.ACME, provider, cert.Domains, challengeOpts...)
	if err != nil {
		return a.fail(ctx, cert, fmt.Errorf("issue certificate: %w", err))
	}

	certDir := filepath.Join(a.cfg.DataDir, "certs", cert.Name)
	if err := certwriter.Write(certDir, certResource.PrivateKey, certResource.Certificate, certResource.IssuerCertificate); err != nil {
		return a.fail(ctx, cert, fmt.Errorf("write certificate: %w", err))
	}
	// Best-effort housekeeping, not a correctness concern: the new
	// certificate is already fully installed and usable regardless of
	// whether old versions get cleaned up, so a Prune failure is logged,
	// not treated as an issuance failure.
	if err := certwriter.Prune(certDir); err != nil {
		slog.Error("prune old certificate versions", "name", cert.Name, "error", err)
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
	// see internal/hook for why. Its outcome is recorded locally
	// (MarkHookResult) and reported to the hub (reportHookResult) as a
	// second, separate checkin - see that method's doc comment for why a
	// second call, not folding this into the checkin above.
	hookErr := hook.Run(ctx, cert.ReloadHook, a.hookTimeoutFor(cert))
	if err := a.st.MarkHookResult(cert.Name, hookErr); err != nil {
		slog.Error("record hook result", "name", cert.Name, "error", err)
	}
	a.reportHookResult(ctx, cert, notBefore, notAfter, serial, hookErr)

	return nil
}

func (a *Agent) fail(ctx context.Context, cert config.SpokeLocalCertConfig, attemptErr error) error {
	consecutiveFailures, markErr := a.st.MarkFailed(cert.Name, attemptErr)
	if markErr != nil {
		slog.Error("record failure locally", "name", cert.Name, "error", markErr)
	}
	if checkinErr := a.checkin(ctx, cert.Name, hubclient.CheckinRequest{
		Domains: cert.Domains, Status: "failed", Error: attemptErr.Error(),
		ConsecutiveFailures: consecutiveFailures,
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
