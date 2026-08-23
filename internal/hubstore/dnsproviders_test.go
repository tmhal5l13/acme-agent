package hubstore

import (
	"errors"
	"testing"

	"github.com/tmhal5l13/acme-agent/config"
)

func TestUpsertDNSProvider_CreatesRetrievableProvider(t *testing.T) {
	st := openTestStore(t)
	cfg := config.DNSProviderConfig{Type: "route53", HostedZoneID: "Z123"}
	if err := st.UpsertDNSProvider("provider-a", cfg); err != nil {
		t.Fatalf("UpsertDNSProvider: %v", err)
	}

	exists, err := st.DNSProviderExists("provider-a")
	if err != nil {
		t.Fatalf("DNSProviderExists: %v", err)
	}
	if !exists {
		t.Fatal("DNSProviderExists returned false right after UpsertDNSProvider")
	}

	all, err := st.AllDNSProviders()
	if err != nil {
		t.Fatalf("AllDNSProviders: %v", err)
	}
	got, ok := all["provider-a"]
	if !ok {
		t.Fatalf("got %+v, missing provider-a", all)
	}
	if got.Type != "route53" || got.HostedZoneID != "Z123" {
		t.Errorf("got %+v, want it to round-trip Type/HostedZoneID", got)
	}
}

func TestUpsertDNSProvider_RejectsEmptyName(t *testing.T) {
	st := openTestStore(t)
	if err := st.UpsertDNSProvider("", providerCfgFixture()); err == nil {
		t.Fatal("UpsertDNSProvider with an empty name: got nil error, want one")
	}
}

func TestUpsertDNSProvider_UpdatesExistingInPlace(t *testing.T) {
	st := openTestStore(t)
	if err := st.UpsertDNSProvider("provider-a", config.DNSProviderConfig{Type: "route53", Region: "us-east-1"}); err != nil {
		t.Fatalf("first UpsertDNSProvider: %v", err)
	}
	if err := st.UpsertDNSProvider("provider-a", config.DNSProviderConfig{Type: "route53", Region: "us-west-2"}); err != nil {
		t.Fatalf("second UpsertDNSProvider: %v", err)
	}

	all, err := st.AllDNSProviders()
	if err != nil {
		t.Fatalf("AllDNSProviders: %v", err)
	}
	if len(all) != 1 || all["provider-a"].Region != "us-west-2" {
		t.Errorf("got %+v, want exactly one provider-a with the updated region", all)
	}
}

func TestDNSProviderExists_UnknownProviderReturnsFalse(t *testing.T) {
	st := openTestStore(t)
	exists, err := st.DNSProviderExists("no-such-provider")
	if err != nil {
		t.Fatalf("DNSProviderExists: %v", err)
	}
	if exists {
		t.Error("got true for a provider that was never created")
	}
}

func TestRemoveDNSProvider_UnknownProviderReturnsErrNotFound(t *testing.T) {
	st := openTestStore(t)
	if err := st.RemoveDNSProvider("no-such-provider"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestRemoveDNSProvider_SucceedsOnceUnreferenced(t *testing.T) {
	st := openTestStore(t)
	if err := st.UpsertDNSProvider("provider-a", providerCfgFixture()); err != nil {
		t.Fatalf("UpsertDNSProvider: %v", err)
	}

	if err := st.RemoveDNSProvider("provider-a"); err != nil {
		t.Fatalf("RemoveDNSProvider: %v", err)
	}

	exists, err := st.DNSProviderExists("provider-a")
	if err != nil {
		t.Fatalf("DNSProviderExists: %v", err)
	}
	if exists {
		t.Error("provider-a still exists after RemoveDNSProvider")
	}
}

func TestRemoveDNSProvider_RefusedWhileReferencedAsDefault(t *testing.T) {
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

	err := st.RemoveDNSProvider("provider-a")
	if !errors.Is(err, ErrInUse) {
		t.Fatalf("got %v, want ErrInUse", err)
	}

	// Must still exist - the rejected attempt shouldn't have removed it.
	exists, existsErr := st.DNSProviderExists("provider-a")
	if existsErr != nil {
		t.Fatalf("DNSProviderExists: %v", existsErr)
	}
	if !exists {
		t.Error("provider-a was removed despite RemoveDNSProvider returning ErrInUse")
	}
}

func TestRemoveDNSProvider_RefusedWhileReferencedAsDomainOverride(t *testing.T) {
	st := openTestStore(t)
	if err := st.UpsertDNSProvider("provider-main", providerCfgFixture()); err != nil {
		t.Fatalf("UpsertDNSProvider provider-main: %v", err)
	}
	if err := st.UpsertDNSProvider("provider-override", providerCfgFixture()); err != nil {
		t.Fatalf("UpsertDNSProvider provider-override: %v", err)
	}
	if err := st.CreateSpoke("spoke-a", "token-a"); err != nil {
		t.Fatalf("CreateSpoke: %v", err)
	}
	cert := config.SpokeCertConfig{
		Name:               "cert-a",
		Domains:            []string{"example.com", "other.example.com"},
		DNSProvider:        "provider-main",
		DomainDNSProviders: map[string]string{"other.example.com": "provider-override"},
	}
	if err := st.UpsertSpokeCert("spoke-a", cert); err != nil {
		t.Fatalf("UpsertSpokeCert: %v", err)
	}

	if err := st.RemoveDNSProvider("provider-override"); !errors.Is(err, ErrInUse) {
		t.Fatalf("got %v, want ErrInUse", err)
	}
	// provider-main is also still referenced (as the default) and must be
	// refused too, not just the override target.
	if err := st.RemoveDNSProvider("provider-main"); !errors.Is(err, ErrInUse) {
		t.Fatalf("got %v, want ErrInUse", err)
	}
}
