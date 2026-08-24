// Package hook runs operator-configured shell commands — a certificate's
// reload_hook, or the hub's notify_hook — bounded by a timeout. cmd is
// interpreted by the OS-native command shell: "sh -c" on Unix, "cmd.exe /C"
// on Windows (see shellCommand in hook_unix.go/hook_windows.go) — the same
// shell syntax an operator would use interactively on that platform.
package hook

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"
)

// waitDelay bounds how long Run waits for stdout/stderr pipes to close after
// a timeout kills the hook's immediate child (the shell). Without this, a
// command like "sleep 5 &" or a shell that forks rather than execs its final
// command can leave an orphaned process holding the pipe open — Cmd.Wait
// then blocks until that orphan exits on its own, silently defeating the
// timeout. See the Cmd.WaitDelay docs in os/exec for the full explanation.
const waitDelay = 5 * time.Second

// Run executes cmd via the OS-native shell, bounded by timeout, and logs its
// combined output. It returns an error if the command fails or times out;
// callers decide what that means for certificate state (see the package doc
// on why a hook failure should not undo a successful issuance).
func Run(ctx context.Context, cmd string, timeout time.Duration) error {
	return RunWithEnv(ctx, cmd, timeout, nil)
}

// RunWithEnv is Run, plus additional environment variables made available
// to cmd — used by the hub's notify_hook to tell the invoked command what
// happened (which spoke, which cert, old/new status, error) without baking
// a specific notification backend into this package. extraEnv is added on
// top of the process's normal environment, not a replacement for it.
func RunWithEnv(ctx context.Context, cmd string, timeout time.Duration, extraEnv map[string]string) error {
	if cmd == "" {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	execCmd := shellCommand(ctx, cmd)
	execCmd.WaitDelay = waitDelay
	if len(extraEnv) > 0 {
		env := os.Environ()
		for k, v := range extraEnv {
			env = append(env, k+"="+v)
		}
		execCmd.Env = env
	}
	var output bytes.Buffer
	execCmd.Stdout = &output
	execCmd.Stderr = &output

	err := execCmd.Run()
	if err != nil {
		slog.Error("hook failed", "cmd", cmd, "output", output.String(), "error", err)
		return fmt.Errorf("hook %q: %w", cmd, err)
	}

	slog.Info("hook succeeded", "cmd", cmd, "output", output.String())
	return nil
}
