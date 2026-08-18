package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

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

// TestDuration_RejectsNegative is the choke-point test for every Duration
// field in both configs at once - see Duration.UnmarshalYAML.
func TestDuration_RejectsNegative(t *testing.T) {
	cases := []struct {
		yaml    string
		wantErr bool
	}{
		{`"1h"`, false},
		{`"0s"`, false},
		{`"-1h"`, true},
		{`"-1ns"`, true},
	}
	for _, c := range cases {
		var d Duration
		err := yaml.Unmarshal([]byte(c.yaml), &d)
		if c.wantErr && err == nil {
			t.Errorf("%s: expected an error, got nil", c.yaml)
		}
		if !c.wantErr && err != nil {
			t.Errorf("%s: unexpected error: %v", c.yaml, err)
		}
	}
}

// TestExpandEnv_OnlyExpandsBracedVars proves ${FOO} expands while bare
// $FOO is left untouched - the actual behavior change from os.ExpandEnv,
// which recognized both.
func TestExpandEnv_OnlyExpandsBracedVars(t *testing.T) {
	t.Setenv("ACME_AGENT_TEST_VAR", "expanded-value")

	got, err := expandEnv("braced: ${ACME_AGENT_TEST_VAR} bare: $ACME_AGENT_TEST_VAR")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "braced: expanded-value bare: $ACME_AGENT_TEST_VAR"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestExpandEnv_UnsetBracedVarErrors proves an unset ${VAR} fails loudly
// at load time instead of silently becoming "" (os.ExpandEnv's behavior),
// naming the missing variable so an operator can actually act on it.
func TestExpandEnv_UnsetBracedVarErrors(t *testing.T) {
	if _, ok := os.LookupEnv("ACME_AGENT_TEST_DEFINITELY_UNSET"); ok {
		t.Fatal("test precondition violated: ACME_AGENT_TEST_DEFINITELY_UNSET is set in this environment")
	}

	_, err := expandEnv("token: ${ACME_AGENT_TEST_DEFINITELY_UNSET}")
	if err == nil {
		t.Fatal("expected an error for an unset env var, got nil")
	}
	if got := err.Error(); !strings.Contains(got, "ACME_AGENT_TEST_DEFINITELY_UNSET") {
		t.Errorf("error %q does not name the missing variable", got)
	}
}

// TestExpandEnv_IgnoresCommentedOutLines proves an unset ${VAR} inside a
// fully commented-out YAML line doesn't error - both example configs in
// deploy/ document optional fields this exact way (e.g.
// "# eab_key_id: "${ACME_EAB_KEY_ID}""), and the error-on-unset behavior
// above would otherwise make that documentation pattern unusable.
func TestExpandEnv_IgnoresCommentedOutLines(t *testing.T) {
	if _, ok := os.LookupEnv("ACME_AGENT_TEST_DEFINITELY_UNSET"); ok {
		t.Fatal("test precondition violated: ACME_AGENT_TEST_DEFINITELY_UNSET is set in this environment")
	}

	got, err := expandEnv("real: value\n  # commented_out: \"${ACME_AGENT_TEST_DEFINITELY_UNSET}\"\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "real: value\n  # commented_out: \"${ACME_AGENT_TEST_DEFINITELY_UNSET}\"\n"
	if got != want {
		t.Errorf("got %q, want %q (commented-out line must be left untouched)", got, want)
	}
}

func TestValidateDomain(t *testing.T) {
	cases := []struct {
		domain  string
		wantErr bool
	}{
		{"example.com", false},
		{"*.example.com", false},
		{"sub.example.com", false},
		{"", true},
		{" ", true},
		{"example.com ", true},
		{" example.com", true},
		{"exa\tmple.com", true},
		{"*.", true},
	}
	for _, c := range cases {
		err := validateDomain(c.domain)
		if c.wantErr && err == nil {
			t.Errorf("%q: expected an error, got nil", c.domain)
		}
		if !c.wantErr && err != nil {
			t.Errorf("%q: unexpected error: %v", c.domain, err)
		}
	}
}

func TestValidateCertName(t *testing.T) {
	cases := []struct {
		name    string
		wantErr bool
	}{
		{"my-cert", false},
		{"radius-cert", false},
		{"", true},
		{".", true},
		{"..", true},
		{"../etc/passwd", true},
		{"a/b", true},
		{"/etc/passwd", true},
		{`a\b`, true},
	}
	for _, c := range cases {
		err := validateCertName(c.name)
		if c.wantErr && err == nil {
			t.Errorf("%q: expected an error, got nil", c.name)
		}
		if !c.wantErr && err != nil {
			t.Errorf("%q: unexpected error: %v", c.name, err)
		}
	}
}

// TestLoadHubConfig_ExampleFileStillLoads and its spoke counterpart (in
// spoke_test.go) are the regression check for the ${VAR}-only change:
// deploy/*.example.yaml already used only the braced form, so restricting
// expansion to it must not break the documented, intended usage pattern.
func TestLoadHubConfig_ExampleFileStillLoads(t *testing.T) {
	for _, v := range []string{
		"CLOUDFLARE_API_TOKEN", "GODADDY_API_KEY", "GODADDY_API_SECRET",
		"PDNS_API_KEY", "BIND_TSIG_KEY_NAME", "BIND_TSIG_SECRET",
	} {
		t.Setenv(v, "test-value")
	}
	// The two spoke tokens must be genuinely distinct - validate() requires
	// token uniqueness across spokes, and the example file uses two
	// different env var names for exactly this reason.
	t.Setenv("SPOKE_FREERADIUS_TOKEN", "test-value-freeradius")
	t.Setenv("SPOKE_NGINX_TOKEN", "test-value-nginx")

	path := repoPath(t, "deploy", "hub-config.example.yaml")
	if _, err := LoadHubConfig(path); err != nil {
		t.Fatalf("LoadHubConfig(%s): %v", path, err)
	}
}

// repoPath resolves a path relative to the module root, since this
// package's own tests run with the package directory as their working
// directory, not the repo root.
func repoPath(t *testing.T, parts ...string) string {
	t.Helper()
	return filepath.Join(append([]string{".."}, parts...)...)
}
