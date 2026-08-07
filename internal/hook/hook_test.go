package hook

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRun_Success(t *testing.T) {
	if err := Run(context.Background(), "true", time.Second); err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
}

func TestRun_Failure(t *testing.T) {
	if err := Run(context.Background(), "exit 1", time.Second); err == nil {
		t.Fatal("expected an error for a failing command, got nil")
	}
}

func TestRun_Timeout(t *testing.T) {
	// sleep 10 outlives both the 50ms context timeout and the package's
	// fixed 5s WaitDelay, so this proves Run returns bounded by WaitDelay
	// rather than blocking until the orphaned sleep exits on its own.
	start := time.Now()
	err := Run(context.Background(), "sleep 10", 50*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected a timeout error, got nil")
	}
	if elapsed > 7*time.Second {
		t.Fatalf("Run took %s, expected it to return within ~5s (WaitDelay), not wait for the full sleep", elapsed)
	}
}

func TestRun_EmptyCommandIsNoop(t *testing.T) {
	if err := Run(context.Background(), "", time.Second); err != nil {
		t.Fatalf("expected empty command to be a no-op, got error: %v", err)
	}
}

func TestRunWithEnv_ExtraVarsAreVisibleToCommand(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "out")
	cmd := "echo \"$ACME_STATUS $ACME_CERT\" > " + marker

	err := RunWithEnv(context.Background(), cmd, time.Second, map[string]string{
		"ACME_STATUS": "failed",
		"ACME_CERT":   "radius-cert",
	})
	if err != nil {
		t.Fatalf("RunWithEnv: %v", err)
	}

	got, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("read marker file: %v", err)
	}
	if want := "failed radius-cert\n"; string(got) != want {
		t.Errorf("got output %q, want %q", got, want)
	}
}

func TestRunWithEnv_NormalEnvironmentStillPresent(t *testing.T) {
	// extraEnv must be additive, not a replacement for the process's own
	// environment — otherwise a reload_hook or notify_hook relying on PATH
	// (to find "systemctl", "curl", etc.) would break.
	marker := filepath.Join(t.TempDir(), "out")
	cmd := "echo \"$PATH\" > " + marker

	err := RunWithEnv(context.Background(), cmd, time.Second, map[string]string{"ACME_STATUS": "active"})
	if err != nil {
		t.Fatalf("RunWithEnv: %v", err)
	}

	got, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("read marker file: %v", err)
	}
	if strings.TrimSpace(string(got)) == "" {
		t.Error("got empty $PATH, want the process's normal PATH to still be present")
	}
}
