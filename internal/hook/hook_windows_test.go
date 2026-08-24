//go:build windows

// These tests exercise Run/RunWithEnv via cmd.exe /C syntax ("%VAR%"
// expansion, cmd.exe redirection) — see hook_test.go for the sh -c
// equivalents.
package hook

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestShellCommand_UsesCmdExe(t *testing.T) {
	cmd := shellCommand(context.Background(), "echo hi")
	if got := cmd.Path; got == "" {
		t.Fatal("expected a resolved executable path, got empty string")
	}
	if len(cmd.Args) != 3 {
		t.Fatalf("got args %v, want exactly 3 (cmd.exe, /C, the command)", cmd.Args)
	}
	if cmd.Args[1] != "/C" {
		t.Errorf("got flag %q, want /C", cmd.Args[1])
	}
	if cmd.Args[2] != "echo hi" {
		t.Errorf("got command %q, want %q", cmd.Args[2], "echo hi")
	}
}

func TestRun_Success(t *testing.T) {
	if err := Run(context.Background(), "exit 0", 5*time.Second); err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
}

func TestRun_Failure(t *testing.T) {
	if err := Run(context.Background(), "exit 1", 5*time.Second); err == nil {
		t.Fatal("expected an error for a failing command, got nil")
	}
}

func TestRun_Timeout(t *testing.T) {
	// ping is used as a portable cmd.exe-builtin-free way to sleep: it ships
	// on every Windows install, unlike "timeout" (which refuses to run with
	// stdin redirected/non-interactive, exactly the environment a test runs
	// in) or "sleep" (not present on stock Windows at all).
	start := time.Now()
	err := Run(context.Background(), "ping -n 11 127.0.0.1 >NUL", 50*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected a timeout error, got nil")
	}
	if elapsed > 7*time.Second {
		t.Fatalf("Run took %s, expected it to return within ~5s (WaitDelay), not wait for the full ping", elapsed)
	}
}

func TestRun_EmptyCommandIsNoop(t *testing.T) {
	if err := Run(context.Background(), "", time.Second); err != nil {
		t.Fatalf("expected empty command to be a no-op, got error: %v", err)
	}
}

func TestRunWithEnv_ExtraVarsAreVisibleToCommand(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "out")
	cmd := "echo %ACME_STATUS% %ACME_CERT% > " + marker

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
	if want := "failed radius-cert"; strings.TrimSpace(string(got)) != want {
		t.Errorf("got output %q, want %q", got, want)
	}
}

func TestRunWithEnv_NormalEnvironmentStillPresent(t *testing.T) {
	// extraEnv must be additive, not a replacement for the process's own
	// environment — otherwise a reload_hook or notify_hook relying on PATH
	// would break.
	marker := filepath.Join(t.TempDir(), "out")
	cmd := "echo %PATH% > " + marker

	err := RunWithEnv(context.Background(), cmd, time.Second, map[string]string{"ACME_STATUS": "active"})
	if err != nil {
		t.Fatalf("RunWithEnv: %v", err)
	}

	got, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("read marker file: %v", err)
	}
	if strings.TrimSpace(string(got)) == "" || strings.TrimSpace(string(got)) == "%PATH%" {
		t.Error("got empty/unexpanded %PATH%, want the process's normal PATH to still be present")
	}
}
