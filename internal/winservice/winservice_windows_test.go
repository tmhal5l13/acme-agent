//go:build windows

package winservice

import (
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
)

// TestHandler_StopCallsStopAndWaitsForDone drives handler.Execute directly
// via hand-fed channels (no real SCM registration needed - that requires
// an actual installed service, out of reach for a unit test) to prove the
// two things RunIfService's doc comment promises: an SCM Stop calls the
// shared stop func, and Execute doesn't report Stopped (or return) until
// the caller closes done - so the SCM can't consider the service down, and
// isn't free to kill it, before the caller's own cleanup has actually
// finished.
func TestHandler_StopCallsStopAndWaitsForDone(t *testing.T) {
	var stopCalled bool
	done := make(chan struct{})
	h := &handler{
		stop: func() { stopCalled = true },
		done: done,
	}

	requests := make(chan svc.ChangeRequest)
	statuses := make(chan svc.Status, 8)
	execDone := make(chan struct{})
	go func() {
		defer close(execDone)
		h.Execute(nil, requests, statuses)
	}()

	if got := <-statuses; got.State != svc.StartPending {
		t.Fatalf("first status = %v, want StartPending", got.State)
	}
	if got := <-statuses; got.State != svc.Running {
		t.Fatalf("second status = %v, want Running", got.State)
	}

	requests <- svc.ChangeRequest{Cmd: svc.Stop}

	if got := <-statuses; got.State != svc.StopPending {
		t.Fatalf("status after Stop = %v, want StopPending", got.State)
	}

	// Execute must not proceed past StopPending until done is closed -
	// give it a beat to (wrongly) race ahead, then confirm it hasn't.
	select {
	case <-execDone:
		t.Fatal("Execute returned before done was closed")
	case <-time.After(50 * time.Millisecond):
	}
	if !stopCalled {
		t.Error("stop was not called after an SCM Stop request")
	}

	close(done)

	if got := <-statuses; got.State != svc.Stopped {
		t.Fatalf("final status = %v, want Stopped", got.State)
	}
	select {
	case <-execDone:
	case <-time.After(time.Second):
		t.Fatal("Execute did not return after done was closed and Stopped was reported")
	}
}

// TestHandler_Interrogate proves an Interrogate request gets its
// CurrentStatus echoed back rather than triggering a shutdown - the SCM
// uses this to poll a service's status without asking it to stop.
func TestHandler_Interrogate(t *testing.T) {
	done := make(chan struct{})
	defer close(done)
	h := &handler{stop: func() {}, done: done}

	requests := make(chan svc.ChangeRequest)
	statuses := make(chan svc.Status, 8)
	go h.Execute(nil, requests, statuses)

	<-statuses // StartPending
	<-statuses // Running

	requests <- svc.ChangeRequest{Cmd: svc.Interrogate, CurrentStatus: svc.Status{State: svc.Running}}

	select {
	case got := <-statuses:
		if got.State != svc.Running {
			t.Errorf("echoed status = %v, want Running", got.State)
		}
	case <-time.After(time.Second):
		t.Fatal("Execute did not echo CurrentStatus back for Interrogate")
	}
}
