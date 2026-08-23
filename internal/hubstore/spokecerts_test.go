package hubstore

import (
	"errors"
	"testing"

	"github.com/tmhal5l13/acme-agent/config"
)

func TestUpsertSpokeCert_UnknownSpokeReturnsErrNotFound(t *testing.T) {
	st := openTestStore(t)
	if err := st.UpsertDNSProvider("provider-a", providerCfgFixture()); err != nil {
		t.Fatalf("UpsertDNSProvider: %v", err)
	}

	err := st.UpsertSpokeCert("no-such-spoke", certFixture("cert-a", "provider-a"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestUpsertSpokeCert_RejectsUnknownDNSProvider(t *testing.T) {
	st := openTestStore(t)
	if err := st.CreateSpoke("spoke-a", "token-a"); err != nil {
		t.Fatalf("CreateSpoke: %v", err)
	}

	err := st.UpsertSpokeCert("spoke-a", certFixture("cert-a", "no-such-provider"))
	if err == nil {
		t.Fatal("UpsertSpokeCert with an unknown dns_provider: got nil error, want one")
	}
}

func TestUpsertSpokeCert_RejectsDomainDNSProviderOverrideForUnlistedDomain(t *testing.T) {
	st := openTestStore(t)
	if err := st.CreateSpoke("spoke-a", "token-a"); err != nil {
		t.Fatalf("CreateSpoke: %v", err)
	}
	if err := st.UpsertDNSProvider("provider-a", providerCfgFixture()); err != nil {
		t.Fatalf("UpsertDNSProvider: %v", err)
	}

	cert := certFixture("cert-a", "provider-a")
	cert.DomainDNSProviders = map[string]string{"not-in-domains.example.com": "provider-a"}

	if err := st.UpsertSpokeCert("spoke-a", cert); err == nil {
		t.Fatal("UpsertSpokeCert with a domain_dns_providers key not in domains: got nil error, want one")
	}
}

func TestUpsertSpokeCert_RejectsUnknownDomainDNSProviderOverrideTarget(t *testing.T) {
	st := openTestStore(t)
	if err := st.CreateSpoke("spoke-a", "token-a"); err != nil {
		t.Fatalf("CreateSpoke: %v", err)
	}
	if err := st.UpsertDNSProvider("provider-a", providerCfgFixture()); err != nil {
		t.Fatalf("UpsertDNSProvider: %v", err)
	}

	cert := certFixture("cert-a", "provider-a")
	cert.DomainDNSProviders = map[string]string{"example.com": "no-such-provider"}

	if err := st.UpsertSpokeCert("spoke-a", cert); err == nil {
		t.Fatal("UpsertSpokeCert with an unknown domain_dns_providers target: got nil error, want one")
	}
}

func TestUpsertSpokeCert_RejectsUnsafeCertName(t *testing.T) {
	st := openTestStore(t)
	if err := st.CreateSpoke("spoke-a", "token-a"); err != nil {
		t.Fatalf("CreateSpoke: %v", err)
	}
	if err := st.UpsertDNSProvider("provider-a", providerCfgFixture()); err != nil {
		t.Fatalf("UpsertDNSProvider: %v", err)
	}

	for _, name := range []string{"../escape", "a/b", "."} {
		cert := certFixture(name, "provider-a")
		if err := st.UpsertSpokeCert("spoke-a", cert); err == nil {
			t.Errorf("UpsertSpokeCert with cert name %q: got nil error, want a path-safety rejection", name)
		}
	}
}

func TestUpsertSpokeCert_RejectsNoDomains(t *testing.T) {
	st := openTestStore(t)
	if err := st.CreateSpoke("spoke-a", "token-a"); err != nil {
		t.Fatalf("CreateSpoke: %v", err)
	}
	if err := st.UpsertDNSProvider("provider-a", providerCfgFixture()); err != nil {
		t.Fatalf("UpsertDNSProvider: %v", err)
	}

	cert := config.SpokeCertConfig{Name: "cert-a", DNSProvider: "provider-a"}
	if err := st.UpsertSpokeCert("spoke-a", cert); err == nil {
		t.Fatal("UpsertSpokeCert with zero domains: got nil error, want one")
	}
}

func TestUpsertSpokeCert_CreatesRetrievableCert(t *testing.T) {
	st := openTestStore(t)
	if err := st.CreateSpoke("spoke-a", "token-a"); err != nil {
		t.Fatalf("CreateSpoke: %v", err)
	}
	if err := st.UpsertDNSProvider("provider-a", providerCfgFixture()); err != nil {
		t.Fatalf("UpsertDNSProvider: %v", err)
	}

	cert := config.SpokeCertConfig{
		Name:               "cert-a",
		Domains:            []string{"example.com", "*.example.com"},
		DNSProvider:        "provider-a",
		DomainDNSProviders: map[string]string{"example.com": "provider-a"},
	}
	if err := st.UpsertSpokeCert("spoke-a", cert); err != nil {
		t.Fatalf("UpsertSpokeCert: %v", err)
	}

	spokes, err := st.AllSpokes()
	if err != nil {
		t.Fatalf("AllSpokes: %v", err)
	}
	if len(spokes) != 1 || len(spokes[0].Certs) != 1 {
		t.Fatalf("got %+v, want one spoke with one cert", spokes)
	}
	got := spokes[0].Certs[0]
	if got.Name != "cert-a" || len(got.Domains) != 2 || got.DNSProvider != "provider-a" || got.DomainDNSProviders["example.com"] != "provider-a" {
		t.Errorf("got %+v, want it to round-trip the fields set above", got)
	}
}

func TestUpsertSpokeCert_UpdatesExistingCertInPlace(t *testing.T) {
	st := openTestStore(t)
	if err := st.CreateSpoke("spoke-a", "token-a"); err != nil {
		t.Fatalf("CreateSpoke: %v", err)
	}
	if err := st.UpsertDNSProvider("provider-a", providerCfgFixture()); err != nil {
		t.Fatalf("UpsertDNSProvider: %v", err)
	}
	if err := st.UpsertSpokeCert("spoke-a", certFixture("cert-a", "provider-a")); err != nil {
		t.Fatalf("first UpsertSpokeCert: %v", err)
	}

	updated := config.SpokeCertConfig{Name: "cert-a", Domains: []string{"updated.example.com"}, DNSProvider: "provider-a"}
	if err := st.UpsertSpokeCert("spoke-a", updated); err != nil {
		t.Fatalf("second UpsertSpokeCert: %v", err)
	}

	spokes, err := st.AllSpokes()
	if err != nil {
		t.Fatalf("AllSpokes: %v", err)
	}
	if len(spokes) != 1 || len(spokes[0].Certs) != 1 {
		t.Fatalf("got %+v, want exactly one cert (an update, not a second row)", spokes)
	}
	if got := spokes[0].Certs[0].Domains; len(got) != 1 || got[0] != "updated.example.com" {
		t.Errorf("got domains %v, want the update to have replaced them", got)
	}
}

func TestRemoveSpokeCert_UnknownCertReturnsErrNotFound(t *testing.T) {
	st := openTestStore(t)
	if err := st.CreateSpoke("spoke-a", "token-a"); err != nil {
		t.Fatalf("CreateSpoke: %v", err)
	}

	if err := st.RemoveSpokeCert("spoke-a", "no-such-cert"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestRemoveSpokeCert_RemovesJustThatCert(t *testing.T) {
	st := openTestStore(t)
	if err := st.CreateSpoke("spoke-a", "token-a"); err != nil {
		t.Fatalf("CreateSpoke: %v", err)
	}
	if err := st.UpsertDNSProvider("provider-a", providerCfgFixture()); err != nil {
		t.Fatalf("UpsertDNSProvider: %v", err)
	}
	if err := st.UpsertSpokeCert("spoke-a", certFixture("cert-a", "provider-a")); err != nil {
		t.Fatalf("UpsertSpokeCert cert-a: %v", err)
	}
	if err := st.UpsertSpokeCert("spoke-a", certFixture("cert-b", "provider-a")); err != nil {
		t.Fatalf("UpsertSpokeCert cert-b: %v", err)
	}

	if err := st.RemoveSpokeCert("spoke-a", "cert-a"); err != nil {
		t.Fatalf("RemoveSpokeCert: %v", err)
	}

	spokes, err := st.AllSpokes()
	if err != nil {
		t.Fatalf("AllSpokes: %v", err)
	}
	if len(spokes) != 1 || len(spokes[0].Certs) != 1 || spokes[0].Certs[0].Name != "cert-b" {
		t.Errorf("got %+v, want only cert-b remaining", spokes)
	}
}
