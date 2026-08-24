//go:build windows

// Package winservice integrates the spoke process with the Windows
// Service Control Manager (SCM) when it's running as a registered Windows
// service - a no-op everywhere else, so callers (cmd/acme-spoke/main.go)
// can call RunIfService unconditionally without their own build tags.
package winservice

import (
	"fmt"
	"log/slog"

	"golang.org/x/sys/windows/svc"
)

// ServiceName is the name RunIfService registers Execute callbacks under,
// and the name deploy/install-spoke.ps1 must register the service as (via
// New-Service -Name) for the two to find each other - the SCM dispatches
// to a running process by matching this string against what was passed to
// StartServiceCtrlDispatcher, which svc.Run does internally.
const ServiceName = "acme-spoke"

// RunIfService starts SCM integration if the current process is running
// as a registered Windows service (svc.IsWindowsService distinguishes
// this from a console/interactive run - e.g. an operator testing with
// -once from a terminal); a no-op that returns immediately otherwise, so
// interactive behavior is completely unchanged.
//
// When it does apply, it runs the SCM's blocking message-read loop
// (svc.Run) in its own goroutine rather than in the caller's, precisely so
// it doesn't block the caller's own agent.Run(ctx) - both need to run
// concurrently: agent.Run(ctx) is the actual work, this is just the
// side-channel telling the SCM the service is alive and forwarding its
// Stop/Shutdown requests into stop.
//
// stop is the same cancel func the caller already derives from
// signal.NotifyContext, so an SCM-issued Stop drives identical shutdown
// logic to an interactive Ctrl+C - no separate shutdown path to keep in
// sync. done must be closed by the caller once whatever stop triggered has
// actually finished; the service handler blocks on it before reporting
// Stopped back to the SCM, so the SCM doesn't consider (and is free to
// force-kill) the service before its cleanup is actually complete.
func RunIfService(stop func(), done <-chan struct{}) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return fmt.Errorf("determine whether running as a windows service: %w", err)
	}
	if !isService {
		return nil
	}

	go func() {
		if err := svc.Run(ServiceName, &handler{stop: stop, done: done}); err != nil {
			slog.Error("windows service run failed", "error", err)
		}
	}()
	return nil
}

// handler implements svc.Handler, translating SCM change requests into
// calls against the shared stop/done pair described on RunIfService.
type handler struct {
	stop func()
	done <-chan struct{}
}

func (h *handler) Execute(_ []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown

	s <- svc.Status{State: svc.StartPending}
	s <- svc.Status{State: svc.Running, Accepts: accepted}

	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			s <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			s <- svc.Status{State: svc.StopPending}
			h.stop()
			<-h.done
			s <- svc.Status{State: svc.Stopped}
			return false, 0
		}
	}
	return false, 0
}
