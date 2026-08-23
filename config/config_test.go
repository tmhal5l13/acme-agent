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

	got, err := expandEnv("braced: ${ACME_AGENT_TEST_VAR} bare: $ACME_AGENT_TEST_VAR", osEnvSource)
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

	_, err := expandEnv("token: ${ACME_AGENT_TEST_DEFINITELY_UNSET}", osEnvSource)
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

	got, err := expandEnv("real: value\n  # commented_out: \"${ACME_AGENT_TEST_DEFINITELY_UNSET}\"\n", osEnvSource)
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
		err := ValidateDomain(c.domain)
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
		err := ValidateCertName(c.name)
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

func TestParseEnvFile_ParsesKeyValueLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.env")
	content := "FOO=bar\n# a comment\n\nBAZ=qux with spaces\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	vars, err := parseEnvFile(path)
	if err != nil {
		t.Fatalf("parseEnvFile: %v", err)
	}
	want := map[string]string{"FOO": "bar", "BAZ": "qux with spaces"}
	if len(vars) != len(want) {
		t.Fatalf("got %v, want %v", vars, want)
	}
	for k, v := range want {
		if vars[k] != v {
			t.Errorf("got %s=%q, want %q", k, vars[k], v)
		}
	}
}

func TestParseEnvFile_RejectsMalformedLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.env")
	if err := os.WriteFile(path, []byte("not-a-valid-line\n"), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	if _, err := parseEnvFile(path); err == nil {
		t.Fatal("expected an error for a line with no '=', got nil")
	}
}

// TestFileEnvSource_FileValueTakesPrecedenceOverProcessEnv proves the
// documented precedence directly: when a name exists in both the file
// and the process's own environment, the file's value wins - the file is
// meant to reflect the operator's current intent, which for a reload is
// exactly the thing that might have just changed.
func TestFileEnvSource_FileValueTakesPrecedenceOverProcessEnv(t *testing.T) {
	t.Setenv("ACME_AGENT_TEST_PRECEDENCE", "from-process-env")

	path := filepath.Join(t.TempDir(), "test.env")
	if err := os.WriteFile(path, []byte("ACME_AGENT_TEST_PRECEDENCE=from-file\n"), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	env, err := fileEnvSource(path)
	if err != nil {
		t.Fatalf("fileEnvSource: %v", err)
	}
	got, ok := env("ACME_AGENT_TEST_PRECEDENCE")
	if !ok || got != "from-file" {
		t.Errorf("got (%q, %v), want (\"from-file\", true)", got, ok)
	}
}

// TestFileEnvSource_FallsBackToProcessEnvForNamesNotInFile proves the
// file isn't a hard replacement for the process environment - only an
// enhancement layered on top, so a var set some other way (e.g. a plain
// systemd Environment= line, not EnvironmentFile=) still resolves.
func TestFileEnvSource_FallsBackToProcessEnvForNamesNotInFile(t *testing.T) {
	t.Setenv("ACME_AGENT_TEST_FALLBACK", "from-process-env")

	path := filepath.Join(t.TempDir(), "test.env")
	if err := os.WriteFile(path, []byte("SOME_OTHER_VAR=irrelevant\n"), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	env, err := fileEnvSource(path)
	if err != nil {
		t.Fatalf("fileEnvSource: %v", err)
	}
	got, ok := env("ACME_AGENT_TEST_FALLBACK")
	if !ok || got != "from-process-env" {
		t.Errorf("got (%q, %v), want (\"from-process-env\", true)", got, ok)
	}
}

// TestFileEnvSource_MissingFileFallsBackToOSEnvSource proves a
// nonexistent env file path isn't an error - not every deployment
// necessarily uses one.
func TestFileEnvSource_MissingFileFallsBackToOSEnvSource(t *testing.T) {
	t.Setenv("ACME_AGENT_TEST_NO_FILE", "still-works")

	env, err := fileEnvSource(filepath.Join(t.TempDir(), "does-not-exist.env"))
	if err != nil {
		t.Fatalf("fileEnvSource: %v", err)
	}
	got, ok := env("ACME_AGENT_TEST_NO_FILE")
	if !ok || got != "still-works" {
		t.Errorf("got (%q, %v), want (\"still-works\", true)", got, ok)
	}
}

// TestFileEnvSource_UnreadableFileFallsBackToOSEnvSource proves a real
// permission error (not just a missing file) also degrades gracefully to
// osEnvSource rather than erroring outright - the case that matters in
// production if the hub's SupplementaryGroups grant (see
// ARCHITECTURE.md "Config hot-reload") is missing or misconfigured: the
// hub should still start and still reload, just without seeing variables
// added to the file since the process started, not fail outright.
func TestFileEnvSource_UnreadableFileFallsBackToOSEnvSource(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, which bypasses file permission checks entirely - this test can't observe a permission error")
	}
	t.Setenv("ACME_AGENT_TEST_UNREADABLE", "still-works")

	path := filepath.Join(t.TempDir(), "test.env")
	if err := os.WriteFile(path, []byte("SOME_VAR=value\n"), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod env file: %v", err)
	}
	t.Cleanup(func() { os.Chmod(path, 0o600) }) // so t.TempDir() can clean it up

	env, err := fileEnvSource(path)
	if err != nil {
		t.Fatalf("fileEnvSource: %v", err)
	}
	got, ok := env("ACME_AGENT_TEST_UNREADABLE")
	if !ok || got != "still-works" {
		t.Errorf("got (%q, %v), want (\"still-works\", true)", got, ok)
	}
}

// TestLoadHubConfig_ResolvesVariableOnlyPresentInEnvFile is the real
// regression test: a ${VAR} resolved purely from acme-hub.env sitting
// next to config.yaml, never set via the process's own environment at
// all (no t.Setenv here) - proving LoadHubConfig genuinely doesn't depend
// on the process's environment already containing it. This is what makes
// it safe to call LoadHubConfig again on every hub SIGHUP
// (hubapi.Server.Reload) and actually see a spoke enrolled - or a DNS
// provider added - after the hub process started, which the process's
// own environment could never gain no matter how many times it's asked
// to reload (see EnvSource's doc comment).
func TestLoadHubConfig_ResolvesVariableOnlyPresentInEnvFile(t *testing.T) {
	if _, ok := os.LookupEnv("ACME_AGENT_TEST_ONLY_IN_ENV_FILE"); ok {
		t.Fatal("test precondition violated: ACME_AGENT_TEST_ONLY_IN_ENV_FILE is set in this environment")
	}

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	// hubEnvFileName, next to configPath - LoadHubConfig's documented
	// convention, not an arbitrary name.
	envPath := filepath.Join(dir, hubEnvFileName)

	if err := os.WriteFile(configPath, []byte(`
listen_addr: "127.0.0.1:8443"
data_dir: /var/lib/acme-hub
status_token: "${ACME_AGENT_TEST_ONLY_IN_ENV_FILE}"
`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(envPath, []byte("ACME_AGENT_TEST_ONLY_IN_ENV_FILE=secret-value\n"), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	cfg, err := LoadHubConfig(configPath)
	if err != nil {
		t.Fatalf("LoadHubConfig: %v", err)
	}
	if cfg.StatusToken != "secret-value" {
		t.Errorf("got status_token %q, want secret-value", cfg.StatusToken)
	}
}

// TestLoadHubConfig_NoEnvFileFallsBackToProcessEnv proves a deployment
// with no acme-hub.env at all still works exactly as before this fix -
// resolving ${VAR} from the process's own environment, same as
// LoadSpokeConfig always has.
func TestLoadHubConfig_NoEnvFileFallsBackToProcessEnv(t *testing.T) {
	t.Setenv("ACME_AGENT_TEST_NO_ENV_FILE", "from-process-env")

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(`
listen_addr: "127.0.0.1:8443"
data_dir: /var/lib/acme-hub
status_token: "${ACME_AGENT_TEST_NO_ENV_FILE}"
`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	// Deliberately no acme-hub.env written in dir.

	cfg, err := LoadHubConfig(configPath)
	if err != nil {
		t.Fatalf("LoadHubConfig: %v", err)
	}
	if cfg.StatusToken != "from-process-env" {
		t.Errorf("got status_token %q, want from-process-env", cfg.StatusToken)
	}
}

// repoPath resolves a path relative to the module root, since this
// package's own tests run with the package directory as their working
// directory, not the repo root.
func repoPath(t *testing.T, parts ...string) string {
	t.Helper()
	return filepath.Join(append([]string{".."}, parts...)...)
}
