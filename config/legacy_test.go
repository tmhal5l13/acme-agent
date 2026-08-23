package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadLegacyDesiredState_ParsesSpokesAndDNSProviders(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "old-config.yaml")
	if err := os.WriteFile(path, []byte(`
dns_providers:
  route53_main:
    type: route53
spokes:
  spoke-a:
    tokens:
      - token-a
    certs:
      - name: cert-a
        domains: [example.com]
        dns_provider: route53_main
`), 0o644); err != nil {
		t.Fatalf("write legacy config: %v", err)
	}

	state, err := LoadLegacyDesiredState(path)
	if err != nil {
		t.Fatalf("LoadLegacyDesiredState: %v", err)
	}
	if _, ok := state.DNSProviders["route53_main"]; !ok {
		t.Errorf("got %+v, missing route53_main", state.DNSProviders)
	}
	spoke, ok := state.Spokes["spoke-a"]
	if !ok {
		t.Fatalf("got %+v, missing spoke-a", state.Spokes)
	}
	if len(spoke.Tokens) != 1 || spoke.Tokens[0] != "token-a" {
		t.Errorf("got tokens %v, want [token-a]", spoke.Tokens)
	}
	if len(spoke.Certs) != 1 || spoke.Certs[0].Name != "cert-a" {
		t.Errorf("got certs %+v, want one cert-a", spoke.Certs)
	}
}

// TestLoadLegacyDesiredState_ExpandsEnvVars proves ${VAR} references still
// resolve from an acme-hub.env file next to path, the same way
// LoadHubConfig's always have - a legacy file's real secret values must
// come back as their actual literal values during import, not the
// unexpanded "${VAR}" string.
func TestLoadLegacyDesiredState_ExpandsEnvVars(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "old-config.yaml")
	envPath := filepath.Join(dir, hubEnvFileName)

	if err := os.WriteFile(path, []byte(`
dns_providers:
  route53_main:
    type: route53
spokes:
  spoke-a:
    tokens:
      - "${ACME_AGENT_TEST_LEGACY_TOKEN}"
    certs:
      - name: cert-a
        domains: [example.com]
        dns_provider: route53_main
`), 0o644); err != nil {
		t.Fatalf("write legacy config: %v", err)
	}
	if err := os.WriteFile(envPath, []byte("ACME_AGENT_TEST_LEGACY_TOKEN=real-secret-value\n"), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	state, err := LoadLegacyDesiredState(path)
	if err != nil {
		t.Fatalf("LoadLegacyDesiredState: %v", err)
	}
	if got := state.Spokes["spoke-a"].Tokens[0]; got != "real-secret-value" {
		t.Errorf("got token %q, want real-secret-value", got)
	}
}

func TestLoadLegacyDesiredState_RejectsDuplicateTokensAcrossSpokes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "old-config.yaml")
	if err := os.WriteFile(path, []byte(`
dns_providers:
  route53_main:
    type: route53
spokes:
  spoke-a:
    tokens: [shared-token]
    certs:
      - name: cert-a
        domains: [example.com]
        dns_provider: route53_main
  spoke-b:
    tokens: [shared-token]
    certs:
      - name: cert-b
        domains: [other.example.com]
        dns_provider: route53_main
`), 0o644); err != nil {
		t.Fatalf("write legacy config: %v", err)
	}

	if _, err := LoadLegacyDesiredState(path); err == nil {
		t.Fatal("expected an error for a token shared across two spokes, got nil")
	}
}

func TestLoadLegacyDesiredState_RejectsUnknownDNSProviderReference(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "old-config.yaml")
	if err := os.WriteFile(path, []byte(`
dns_providers: {}
spokes:
  spoke-a:
    tokens: [token-a]
    certs:
      - name: cert-a
        domains: [example.com]
        dns_provider: does-not-exist
`), 0o644); err != nil {
		t.Fatalf("write legacy config: %v", err)
	}

	if _, err := LoadLegacyDesiredState(path); err == nil {
		t.Fatal("expected an error for a cert referencing an undefined dns_provider, got nil")
	}
}

func TestLoadLegacyDesiredState_RejectsUnsafeCertName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "old-config.yaml")
	if err := os.WriteFile(path, []byte(`
dns_providers:
  route53_main:
    type: route53
spokes:
  spoke-a:
    tokens: [token-a]
    certs:
      - name: "../escape"
        domains: [example.com]
        dns_provider: route53_main
`), 0o644); err != nil {
		t.Fatalf("write legacy config: %v", err)
	}

	if _, err := LoadLegacyDesiredState(path); err == nil {
		t.Fatal("expected an error for a path-unsafe cert name, got nil")
	}
}
