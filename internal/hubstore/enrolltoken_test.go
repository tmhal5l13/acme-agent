package hubstore

import (
	"sync"
	"testing"
	"time"
)

func TestLookupEnrollmentToken_FindsUnredeemedSecret(t *testing.T) {
	st := openTestStore(t)
	now := time.Now().UTC()
	if err := st.InsertEnrollmentToken("secret-a", "spoke-a", "bearer-a", now.Add(time.Hour)); err != nil {
		t.Fatalf("InsertEnrollmentToken: %v", err)
	}

	spokeID, bearerToken, ok, err := st.LookupEnrollmentToken("secret-a", now)
	if err != nil {
		t.Fatalf("LookupEnrollmentToken: %v", err)
	}
	if !ok {
		t.Fatal("got ok=false for a freshly-inserted, unexpired secret, want true")
	}
	if spokeID != "spoke-a" || bearerToken != "bearer-a" {
		t.Errorf("got spoke_id=%q bearer_token=%q, want spoke-a/bearer-a", spokeID, bearerToken)
	}
}

// TestInsertEnrollmentToken_NormalizesNonUTCExpiry guards a real bug: a
// caller passing a non-UTC expiresAt (e.g. local wall-clock time) used to
// break the expires_at > ? comparison LookupEnrollmentToken/
// RedeemEnrollmentToken rely on, since SQLite compares these TIMESTAMP
// columns as text and a local-zone offset doesn't sort the way its actual
// instant compares against a UTC "now". Using a fixed non-UTC zone here
// (rather than whatever the test machine's local zone happens to be)
// makes this deterministic regardless of where it runs.
func TestInsertEnrollmentToken_NormalizesNonUTCExpiry(t *testing.T) {
	st := openTestStore(t)
	loc := time.FixedZone("UTC-7", -7*60*60)
	expiresAt := time.Now().In(loc).Add(time.Hour)

	if err := st.InsertEnrollmentToken("secret-a", "spoke-a", "bearer-a", expiresAt); err != nil {
		t.Fatalf("InsertEnrollmentToken: %v", err)
	}

	if _, _, ok, err := st.LookupEnrollmentToken("secret-a", time.Now().UTC()); err != nil || !ok {
		t.Fatalf("LookupEnrollmentToken: ok=%v err=%v, want true/nil - a non-UTC expiresAt must still compare correctly", ok, err)
	}
}

func TestLookupEnrollmentToken_UnknownSecretNotFound(t *testing.T) {
	st := openTestStore(t)
	_, _, ok, err := st.LookupEnrollmentToken("no-such-secret", time.Now().UTC())
	if err != nil {
		t.Fatalf("LookupEnrollmentToken: %v", err)
	}
	if ok {
		t.Error("got ok=true for a secret that was never inserted, want false")
	}
}

func TestLookupEnrollmentToken_ExpiredNotFound(t *testing.T) {
	st := openTestStore(t)
	now := time.Now().UTC()
	if err := st.InsertEnrollmentToken("secret-a", "spoke-a", "bearer-a", now.Add(-time.Minute)); err != nil {
		t.Fatalf("InsertEnrollmentToken: %v", err)
	}

	_, _, ok, err := st.LookupEnrollmentToken("secret-a", now)
	if err != nil {
		t.Fatalf("LookupEnrollmentToken: %v", err)
	}
	if ok {
		t.Error("got ok=true for an already-expired secret, want false")
	}
}

// TestLookupEnrollmentToken_DoesNotConsume is the property that makes it
// safe for a caller to look up the associated spoke before deciding
// whether to actually redeem - see LookupEnrollmentToken's doc comment.
func TestLookupEnrollmentToken_DoesNotConsume(t *testing.T) {
	st := openTestStore(t)
	now := time.Now().UTC()
	if err := st.InsertEnrollmentToken("secret-a", "spoke-a", "bearer-a", now.Add(time.Hour)); err != nil {
		t.Fatalf("InsertEnrollmentToken: %v", err)
	}

	if _, _, ok, err := st.LookupEnrollmentToken("secret-a", now); err != nil || !ok {
		t.Fatalf("first LookupEnrollmentToken: ok=%v err=%v, want true/nil", ok, err)
	}
	if _, _, ok, err := st.LookupEnrollmentToken("secret-a", now); err != nil || !ok {
		t.Fatalf("second LookupEnrollmentToken: ok=%v err=%v, want true/nil - a lookup must not consume the secret", ok, err)
	}
}

func TestRedeemEnrollmentToken_SucceedsOnce(t *testing.T) {
	st := openTestStore(t)
	now := time.Now().UTC()
	if err := st.InsertEnrollmentToken("secret-a", "spoke-a", "bearer-a", now.Add(time.Hour)); err != nil {
		t.Fatalf("InsertEnrollmentToken: %v", err)
	}

	ok, err := st.RedeemEnrollmentToken("secret-a", now)
	if err != nil {
		t.Fatalf("RedeemEnrollmentToken: %v", err)
	}
	if !ok {
		t.Fatal("got ok=false for a freshly-inserted secret's first redemption, want true")
	}

	// A lookup afterward must no longer find it - it's been consumed.
	if _, _, ok, err := st.LookupEnrollmentToken("secret-a", now); err != nil || ok {
		t.Errorf("LookupEnrollmentToken after redemption: ok=%v err=%v, want false/nil", ok, err)
	}
}

func TestRedeemEnrollmentToken_FailsOnSecondAttempt(t *testing.T) {
	st := openTestStore(t)
	now := time.Now().UTC()
	if err := st.InsertEnrollmentToken("secret-a", "spoke-a", "bearer-a", now.Add(time.Hour)); err != nil {
		t.Fatalf("InsertEnrollmentToken: %v", err)
	}

	if ok, err := st.RedeemEnrollmentToken("secret-a", now); err != nil || !ok {
		t.Fatalf("first RedeemEnrollmentToken: ok=%v err=%v, want true/nil", ok, err)
	}

	ok, err := st.RedeemEnrollmentToken("secret-a", now)
	if err != nil {
		t.Fatalf("second RedeemEnrollmentToken: %v", err)
	}
	if ok {
		t.Error("got ok=true redeeming an already-redeemed secret a second time, want false")
	}
}

func TestRedeemEnrollmentToken_FailsWhenExpired(t *testing.T) {
	st := openTestStore(t)
	now := time.Now().UTC()
	if err := st.InsertEnrollmentToken("secret-a", "spoke-a", "bearer-a", now.Add(-time.Minute)); err != nil {
		t.Fatalf("InsertEnrollmentToken: %v", err)
	}

	ok, err := st.RedeemEnrollmentToken("secret-a", now)
	if err != nil {
		t.Fatalf("RedeemEnrollmentToken: %v", err)
	}
	if ok {
		t.Error("got ok=true redeeming an already-expired secret, want false")
	}
}

func TestRedeemEnrollmentToken_FailsForUnknownSecret(t *testing.T) {
	st := openTestStore(t)
	ok, err := st.RedeemEnrollmentToken("no-such-secret", time.Now().UTC())
	if err != nil {
		t.Fatalf("RedeemEnrollmentToken: %v", err)
	}
	if ok {
		t.Error("got ok=true redeeming a secret that was never inserted, want false")
	}
}

// TestRedeemEnrollmentToken_ConcurrentCallersOnlyOneSucceeds is the
// real-behavior proof this whole feature depends on for its one-time
// guarantee - mirrors TestClaim_ConcurrentCallersOnlyOneSucceeds exactly:
// real goroutines racing against one real temp-file database, not an
// assumption that the WHERE-guarded UPDATE is atomic.
func TestRedeemEnrollmentToken_ConcurrentCallersOnlyOneSucceeds(t *testing.T) {
	st := openTestStore(t)
	now := time.Now().UTC()
	if err := st.InsertEnrollmentToken("secret-a", "spoke-a", "bearer-a", now.Add(time.Hour)); err != nil {
		t.Fatalf("InsertEnrollmentToken: %v", err)
	}

	const attempts = 20
	var wg sync.WaitGroup
	results := make(chan bool, attempts)

	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			defer wg.Done()
			ok, err := st.RedeemEnrollmentToken("secret-a", time.Now().UTC())
			if err != nil {
				t.Errorf("RedeemEnrollmentToken: %v", err)
				return
			}
			results <- ok
		}()
	}
	wg.Wait()
	close(results)

	successes := 0
	for ok := range results {
		if ok {
			successes++
		}
	}
	if successes != 1 {
		t.Errorf("got %d successful redemptions out of %d concurrent attempts, want exactly 1", successes, attempts)
	}
}
