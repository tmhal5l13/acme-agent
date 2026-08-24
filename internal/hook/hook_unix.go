//go:build !windows

package hook

import (
	"context"
	"os/exec"
)

// shellCommand builds the command that will interpret cmd on this platform.
func shellCommand(ctx context.Context, cmd string) *exec.Cmd {
	return exec.CommandContext(ctx, "sh", "-c", cmd)
}
