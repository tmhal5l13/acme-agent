package config

import "testing"

func TestACMEConfig_ValidEnvironmentAlone(t *testing.T) {
	for _, env := range []string{"staging", "production"} {
		if err := (ACMEConfig{Environment: env}).validate(); err != nil {
			t.Errorf("environment %q: unexpected error: %v", env, err)
		}
	}
}

func TestACMEConfig_InvalidEnvironmentErrors(t *testing.T) {
	if err := (ACMEConfig{Environment: "not-a-real-environment"}).validate(); err == nil {
		t.Error("expected an error for an invalid environment, got nil")
	}
}

func TestACMEConfig_DirectoryURLAloneIsValid(t *testing.T) {
	if err := (ACMEConfig{DirectoryURL: "https://private-ca.example.com/acme/directory"}).validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestACMEConfig_EnvironmentAndDirectoryURLTogetherErrors(t *testing.T) {
	cfg := ACMEConfig{Environment: "staging", DirectoryURL: "https://private-ca.example.com/acme/directory"}
	if err := cfg.validate(); err == nil {
		t.Error("expected an error when both environment and directory_url are set, got nil")
	}
}

func TestACMEConfig_NeitherEnvironmentNorDirectoryURLErrors(t *testing.T) {
	if err := (ACMEConfig{}).validate(); err == nil {
		t.Error("expected an error when neither environment nor directory_url is set, got nil")
	}
}

// TestACMEConfig_EABBothOrNeither guards the actual failure mode EAB's
// validation exists to catch: supplying only one of the two required
// values (e.g. a copy-paste that drops the HMAC key) would otherwise reach
// the CA as a malformed EAB request instead of failing locally with a
// clear message.
func TestACMEConfig_EABBothOrNeither(t *testing.T) {
	cases := []struct {
		name    string
		keyID   string
		hmacKey string
		wantErr bool
	}{
		{"neither set", "", "", false},
		{"both set", "kid-123", "aGVsbG8=", false},
		{"only key id", "kid-123", "", true},
		{"only hmac key", "", "aGVsbG8=", true},
	}
	for _, c := range cases {
		cfg := ACMEConfig{Environment: "staging", EABKeyID: c.keyID, EABHMACKey: c.hmacKey}
		err := cfg.validate()
		if c.wantErr && err == nil {
			t.Errorf("%s: expected an error, got nil", c.name)
		}
		if !c.wantErr && err != nil {
			t.Errorf("%s: unexpected error: %v", c.name, err)
		}
	}
}
