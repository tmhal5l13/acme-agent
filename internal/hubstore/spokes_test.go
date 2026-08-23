package hubstore

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestCreateSpoke_CreatesSpokeAndToken(t *testing.T) {
	st := openTestStore(t)
	if err := st.CreateSpoke("spoke-a", "token-a"); err != nil {
		t.Fatalf("CreateSpoke: %v", err)
	}

	exists, err := st.SpokeExists("spoke-a")
	if err != nil {
		t.Fatalf("SpokeExists: %v", err)
	}
	if !exists {
		t.Fatal("SpokeExists returned false right after CreateSpoke")
	}

	spokes, err := st.AllSpokes()
	if err != nil {
		t.Fatalf("AllSpokes: %v", err)
	}
	if len(spokes) != 1 || spokes[0].ID != "spoke-a" || len(spokes[0].Tokens) != 1 || spokes[0].Tokens[0] != "token-a" {
		t.Errorf("got %+v, want one spoke-a with token token-a", spokes)
	}
}

func TestCreateSpoke_RejectsDuplicateID(t *testing.T) {
	st := openTestStore(t)
	if err := st.CreateSpoke("spoke-a", "token-a"); err != nil {
		t.Fatalf("first CreateSpoke: %v", err)
	}

	err := st.CreateSpoke("spoke-a", "token-b")
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("got %v, want ErrAlreadyExists", err)
	}

	// The rejected attempt must not have overwritten the original token,
	// and must not have left a dangling spoke_tokens row for token-b -
	// both-or-neither, per CreateSpoke's doc comment.
	spokes, err := st.AllSpokes()
	if err != nil {
		t.Fatalf("AllSpokes: %v", err)
	}
	if len(spokes) != 1 || len(spokes[0].Tokens) != 1 || spokes[0].Tokens[0] != "token-a" {
		t.Errorf("got %+v, want exactly one spoke-a still holding only token-a", spokes)
	}
}

func TestCreateSpoke_RejectsTokenAlreadyUsedByAnotherSpoke(t *testing.T) {
	st := openTestStore(t)
	if err := st.CreateSpoke("spoke-a", "token-a"); err != nil {
		t.Fatalf("first CreateSpoke: %v", err)
	}

	err := st.CreateSpoke("spoke-b", "token-a")
	if !errors.Is(err, ErrTokenInUse) {
		t.Fatalf("got %v, want ErrTokenInUse", err)
	}

	// spoke-b must not have been created at all - both-or-neither.
	exists, err := st.SpokeExists("spoke-b")
	if err != nil {
		t.Fatalf("SpokeExists: %v", err)
	}
	if exists {
		t.Error("spoke-b exists after a rejected CreateSpoke, want it not created at all")
	}
}

// TestCreateSpoke_ConcurrentDuplicateTokenOnlyOneSucceeds is the
// real-behavior proof this project's discipline demands for anything
// claiming atomicity - mirrors TestClaim_ConcurrentCallersOnlyOneSucceeds
// and TestRedeemEnrollmentToken_ConcurrentCallersOnlyOneSucceeds exactly:
// real goroutines, real temp-file database, not just an assumption that a
// PRIMARY KEY constraint serializes correctly under concurrent writers.
func TestCreateSpoke_ConcurrentDuplicateTokenOnlyOneSucceeds(t *testing.T) {
	st := openTestStore(t)

	const attempts = 20
	var wg sync.WaitGroup
	results := make(chan bool, attempts)

	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		i := i
		go func() {
			defer wg.Done()
			spokeID := fakeSpokeID(i)
			err := st.CreateSpoke(spokeID, "contested-token")
			if err == nil {
				results <- true
				return
			}
			if !errors.Is(err, ErrTokenInUse) {
				t.Errorf("CreateSpoke(%q): got %v, want nil or ErrTokenInUse", spokeID, err)
			}
			results <- false
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
		t.Errorf("got %d successful CreateSpoke calls racing for one token out of %d attempts, want exactly 1", successes, attempts)
	}
}

func fakeSpokeID(i int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	return "spoke-" + string(letters[i%len(letters)]) + string(letters[i/len(letters)%len(letters)])
}

func TestDeleteSpoke_CascadesTokensCertsAndObservedState(t *testing.T) {
	st := openTestStore(t)
	if err := st.CreateSpoke("spoke-a", "token-a"); err != nil {
		t.Fatalf("CreateSpoke: %v", err)
	}
	if err := st.UpsertDNSProvider("provider-a", providerCfgFixture()); err != nil {
		t.Fatalf("UpsertDNSProvider: %v", err)
	}
	if err := st.UpsertSpokeCert("spoke-a", certFixture("cert-a", "provider-a")); err != nil {
		t.Fatalf("UpsertSpokeCert: %v", err)
	}
	now := time.Now().UTC()
	if err := st.CheckinActive("spoke-a", "cert-a", now, now, "serial"); err != nil {
		t.Fatalf("CheckinActive: %v", err)
	}
	if err := st.InsertEnrollmentToken("secret-a", "spoke-a", "bearer-a", now.Add(time.Hour)); err != nil {
		t.Fatalf("InsertEnrollmentToken: %v", err)
	}

	if err := st.DeleteSpoke("spoke-a"); err != nil {
		t.Fatalf("DeleteSpoke: %v", err)
	}

	if exists, _ := st.SpokeExists("spoke-a"); exists {
		t.Error("spoke-a still exists after DeleteSpoke")
	}
	spokes, err := st.AllSpokes()
	if err != nil {
		t.Fatalf("AllSpokes: %v", err)
	}
	if len(spokes) != 0 {
		t.Errorf("got %d spokes after deleting the only one, want 0", len(spokes))
	}
	if _, err := st.Get("spoke-a", "cert-a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get on observed state after DeleteSpoke: got %v, want ErrNotFound", err)
	}
	if _, _, ok, err := st.LookupEnrollmentToken("secret-a", time.Now().UTC()); err != nil || ok {
		t.Errorf("LookupEnrollmentToken after DeleteSpoke: ok=%v err=%v, want false/nil", ok, err)
	}
}

func TestDeleteSpoke_UnknownSpokeReturnsErrNotFound(t *testing.T) {
	st := openTestStore(t)
	if err := st.DeleteSpoke("no-such-spoke"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestAddSpokeToken_UnknownSpokeReturnsErrNotFound(t *testing.T) {
	st := openTestStore(t)
	if err := st.AddSpokeToken("no-such-spoke", "token-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestAddSpokeToken_RejectsTokenAlreadyInUse(t *testing.T) {
	st := openTestStore(t)
	if err := st.CreateSpoke("spoke-a", "token-a"); err != nil {
		t.Fatalf("CreateSpoke: %v", err)
	}
	if err := st.CreateSpoke("spoke-b", "token-b"); err != nil {
		t.Fatalf("CreateSpoke: %v", err)
	}

	if err := st.AddSpokeToken("spoke-a", "token-b"); !errors.Is(err, ErrTokenInUse) {
		t.Fatalf("got %v, want ErrTokenInUse", err)
	}
}

func TestAddSpokeToken_AddsAlongsideExisting(t *testing.T) {
	st := openTestStore(t)
	if err := st.CreateSpoke("spoke-a", "token-a"); err != nil {
		t.Fatalf("CreateSpoke: %v", err)
	}
	if err := st.AddSpokeToken("spoke-a", "token-a2"); err != nil {
		t.Fatalf("AddSpokeToken: %v", err)
	}

	spokes, err := st.AllSpokes()
	if err != nil {
		t.Fatalf("AllSpokes: %v", err)
	}
	if len(spokes) != 1 || len(spokes[0].Tokens) != 2 {
		t.Fatalf("got %+v, want spoke-a with 2 tokens", spokes)
	}
	byToken := map[string]bool{spokes[0].Tokens[0]: true, spokes[0].Tokens[1]: true}
	if !byToken["token-a"] || !byToken["token-a2"] {
		t.Errorf("got tokens %v, want both token-a and token-a2 present", spokes[0].Tokens)
	}
}

func TestRemoveSpokeToken_RefusesToLeaveZeroTokens(t *testing.T) {
	st := openTestStore(t)
	if err := st.CreateSpoke("spoke-a", "token-a"); err != nil {
		t.Fatalf("CreateSpoke: %v", err)
	}

	err := st.RemoveSpokeToken("spoke-a", "token-a")
	if !errors.Is(err, ErrLastToken) {
		t.Fatalf("got %v, want ErrLastToken", err)
	}

	spokes, err := st.AllSpokes()
	if err != nil {
		t.Fatalf("AllSpokes: %v", err)
	}
	if len(spokes) != 1 || len(spokes[0].Tokens) != 1 {
		t.Errorf("token-a was removed despite being the last one - got %+v", spokes)
	}
}

func TestRemoveSpokeToken_SucceedsWithTwoOrMoreRemaining(t *testing.T) {
	st := openTestStore(t)
	if err := st.CreateSpoke("spoke-a", "token-a"); err != nil {
		t.Fatalf("CreateSpoke: %v", err)
	}
	if err := st.AddSpokeToken("spoke-a", "token-a2"); err != nil {
		t.Fatalf("AddSpokeToken: %v", err)
	}

	if err := st.RemoveSpokeToken("spoke-a", "token-a"); err != nil {
		t.Fatalf("RemoveSpokeToken: %v", err)
	}

	spokes, err := st.AllSpokes()
	if err != nil {
		t.Fatalf("AllSpokes: %v", err)
	}
	if len(spokes) != 1 || len(spokes[0].Tokens) != 1 || spokes[0].Tokens[0] != "token-a2" {
		t.Errorf("got %+v, want spoke-a with only token-a2 remaining", spokes)
	}
}

func TestRemoveSpokeToken_UnknownTokenReturnsErrNotFound(t *testing.T) {
	st := openTestStore(t)
	if err := st.CreateSpoke("spoke-a", "token-a"); err != nil {
		t.Fatalf("CreateSpoke: %v", err)
	}
	if err := st.AddSpokeToken("spoke-a", "token-a2"); err != nil {
		t.Fatalf("AddSpokeToken: %v", err)
	}

	if err := st.RemoveSpokeToken("spoke-a", "no-such-token"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestAllSpokes_ReturnsTokensAndCertsTogether(t *testing.T) {
	st := openTestStore(t)
	if err := st.UpsertDNSProvider("provider-a", providerCfgFixture()); err != nil {
		t.Fatalf("UpsertDNSProvider: %v", err)
	}
	if err := st.CreateSpoke("spoke-a", "token-a"); err != nil {
		t.Fatalf("CreateSpoke: %v", err)
	}
	if err := st.UpsertSpokeCert("spoke-a", certFixture("cert-a", "provider-a")); err != nil {
		t.Fatalf("UpsertSpokeCert: %v", err)
	}
	if err := st.CreateSpoke("spoke-b", "token-b"); err != nil {
		t.Fatalf("CreateSpoke: %v", err)
	}

	spokes, err := st.AllSpokes()
	if err != nil {
		t.Fatalf("AllSpokes: %v", err)
	}
	if len(spokes) != 2 {
		t.Fatalf("got %d spokes, want 2", len(spokes))
	}

	byID := make(map[string]Spoke, len(spokes))
	for _, sp := range spokes {
		byID[sp.ID] = sp
	}
	if len(byID["spoke-a"].Certs) != 1 || byID["spoke-a"].Certs[0].Name != "cert-a" {
		t.Errorf("spoke-a: got certs %+v, want one cert-a", byID["spoke-a"].Certs)
	}
	if len(byID["spoke-b"].Certs) != 0 {
		t.Errorf("spoke-b: got certs %+v, want none", byID["spoke-b"].Certs)
	}
}
