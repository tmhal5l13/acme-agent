package hubapi

import "testing"

// TestAuth_NearMissTokenRejected is the functional companion to authorize's
// doc comment on why bearer token matching is a plain map lookup rather
// than a crypto/subtle.ConstantTimeCompare loop: a token that's almost
// right (same length, one character different) must be rejected exactly
// like any other unknown token, proving the match really is exact rather
// than some kind of fuzzy/prefix comparison. This doesn't (and can't, in
// a unit test) prove anything about timing - see the doc comment in
// auth.go for that argument - it only proves the functional behavior is
// what's claimed.
func TestAuth_NearMissTokenRejected(t *testing.T) {
	s := newTestServer(t, testConfig(), nil)
	// testConfig's real token is "token-a".
	resp := doRequest(s, "GET", "/v1/certs/cert-a/due", "token-b", nil)
	if resp.Code != 401 {
		t.Fatalf("got status %d, want 401 for a near-miss token", resp.Code)
	}
}

// TestAuth_EitherTokenDuringRotationAuthenticates proves the actual point
// of SpokeEntry.Tokens being a list: a spoke with two tokens configured
// (the state a rotation grace period leaves it in, see PlanRotation)
// authenticates successfully with either one, not just the first.
func TestAuth_EitherTokenDuringRotationAuthenticates(t *testing.T) {
	cfg := testConfig()
	spoke := cfg.Spokes["spoke-a"]
	spoke.Tokens = []string{"token-a", "token-a-new"}
	cfg.Spokes["spoke-a"] = spoke

	s := newTestServer(t, cfg, nil)

	for _, token := range []string{"token-a", "token-a-new"} {
		resp := doRequest(s, "GET", "/v1/certs/cert-a/due", token, nil)
		if resp.Code == 401 {
			t.Errorf("token %q: got 401, want it to authenticate successfully during the rotation grace period", token)
		}
	}

	resp := doRequest(s, "GET", "/v1/certs/cert-a/due", "token-a-old-and-removed", nil)
	if resp.Code != 401 {
		t.Errorf("got status %d for a token not in the spoke's list, want 401", resp.Code)
	}
}
