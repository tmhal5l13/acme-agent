package hubapi

import (
	"testing"
	"time"
)

func TestJitterFor_ZeroMaxIsZero(t *testing.T) {
	if got := jitterFor("spoke-a", "cert-a", 0); got != 0 {
		t.Errorf("got %s, want 0", got)
	}
}

func TestJitterFor_WithinBounds(t *testing.T) {
	maxJitter := 48 * time.Hour
	cases := []struct{ spoke, cert string }{
		{"spoke-a", "cert-a"}, {"spoke-a", "cert-b"}, {"spoke-b", "cert-a"},
		{"freeradius-spoke", "radius-cert"}, {"nginx-spoke", "nginx-cert"},
	}
	for _, c := range cases {
		got := jitterFor(c.spoke, c.cert, maxJitter)
		if got < 0 || got >= maxJitter {
			t.Errorf("jitterFor(%q, %q, %s) = %s, want in [0, %s)", c.spoke, c.cert, maxJitter, got, maxJitter)
		}
	}
}

// TestJitterFor_Stable proves the same spoke+cert always gets the same
// jitter — this is what stops a certificate's due status from flip-flopping
// between polls, which would happen if jitter were re-rolled every call.
func TestJitterFor_Stable(t *testing.T) {
	first := jitterFor("spoke-a", "cert-a", 48*time.Hour)
	for i := 0; i < 5; i++ {
		if got := jitterFor("spoke-a", "cert-a", 48*time.Hour); got != first {
			t.Fatalf("call %d: got %s, want %s (same as the first call)", i, got, first)
		}
	}
}

// TestJitterFor_SpreadsAcrossCerts proves different certificates actually
// get different jitter — the entire point (a fleet spreading out) fails
// silently if every cert happens to land on the same offset.
func TestJitterFor_SpreadsAcrossCerts(t *testing.T) {
	maxJitter := 48 * time.Hour
	seen := make(map[time.Duration]bool)
	for i := 0; i < 20; i++ {
		certName := "cert-" + string(rune('a'+i))
		seen[jitterFor("spoke-a", certName, maxJitter)] = true
	}
	if len(seen) < 15 { // allow for rare hash collisions, not an exact count
		t.Errorf("got only %d distinct jitter values across 20 certs, want most of them to differ", len(seen))
	}
}

func TestJitterFor_DifferentSpokesSameCertNameDiffer(t *testing.T) {
	a := jitterFor("spoke-a", "same-cert-name", 48*time.Hour)
	b := jitterFor("spoke-b", "same-cert-name", 48*time.Hour)
	if a == b {
		t.Error("two different spokes with identically-named certs got the same jitter — spoke identity isn't actually factored in")
	}
}
