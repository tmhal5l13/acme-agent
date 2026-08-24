//go:build windows

package hook

import (
	"context"
	"os/exec"
)

// shellCommand builds the command that will interpret cmd on this platform.
// cmd.exe is what's actually present on a stock Windows install — there is
// no "sh" there, and requiring one would mean requiring an extra install
// (WSL, Git Bash, etc.) just to run a reload_hook.
func shellCommand(ctx context.Context, cmd string) *exec.Cmd {
	return exec.CommandContext(ctx, "cmd.exe", "/C", cmd)
}
