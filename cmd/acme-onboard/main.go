// Command acme-onboard adds one certificate to one spoke: a scriptable,
// non-interactive alternative to the hub's web admin UI, for the same
// same-host, direct-database-access operational model
// acme-hub --generate-token already uses. Writes the hub side (spoke,
// token, certificate assignment) straight into the hub's database — see
// internal/onboard — and, unless told otherwise, writes the new spoke's
// complete config.yaml to a file for you to copy over.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/tmhal5l13/acme-agent/config"
	"github.com/tmhal5l13/acme-agent/internal/hubstore"
	"github.com/tmhal5l13/acme-agent/internal/onboard"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	hubConfigPath := flag.String("hub-config", "", "path to the hub's existing config.yaml (read-only, never modified)")
	spokeID := flag.String("spoke-id", "", "spoke identifier, e.g. freeradius-spoke")
	certName := flag.String("cert-name", "", "certificate name, must be unique within this spoke")
	domains := flag.String("domains", "", "comma-separated domains, e.g. radius.example.com or example.com,*.example.com")
	dnsProvider := flag.String("dns-provider", "", "name of an entry already defined under the hub's dns_providers")
	hubURL := flag.String("hub-url", "", "URL this spoke will use to reach the hub, e.g. https://192.0.2.10:8443")
	hubTLSCertFile := flag.String("hub-tls-cert-file", "/etc/acme-spoke/hub-cert.pem", "local path, on this new spoke, where you'll copy the hub's certificate to")
	reloadHook := flag.String("reload-hook", "", "optional local reload command, e.g. \"systemctl reload nginx\"")
	acmeEmail := flag.String("acme-email", "", "ACME account email for this spoke")
	acmeEnv := flag.String("acme-environment", "staging", "staging or production")
	spokeConfigOut := flag.String("spoke-config-out", "", "write the generated spoke config.yaml here instead of printing it")
	flag.Parse()

	if *hubConfigPath == "" {
		return fmt.Errorf("--hub-config is required")
	}

	hubCfg, err := config.LoadHubConfig(*hubConfigPath)
	if err != nil {
		return fmt.Errorf("load hub config: %w", err)
	}

	st, err := hubstore.Open(hubCfg.DBPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	var domainList []string
	for _, d := range strings.Split(*domains, ",") {
		if d = strings.TrimSpace(d); d != "" {
			domainList = append(domainList, d)
		}
	}

	result, err := onboard.Plan(st, onboard.Request{
		SpokeID:        *spokeID,
		CertName:       *certName,
		Domains:        domainList,
		DNSProvider:    *dnsProvider,
		HubURL:         *hubURL,
		HubTLSCertFile: *hubTLSCertFile,
		ReloadHook:     *reloadHook,
		ACMEEmail:      *acmeEmail,
		ACMEEnv:        *acmeEnv,
	})
	if err != nil {
		return err
	}

	if result.IsNewSpoke {
		fmt.Printf("Created spoke %q on the hub.\n", *spokeID)
	} else {
		fmt.Printf("Added certificate %q to existing spoke %q.\n", *certName, *spokeID)
	}
	fmt.Println("This takes effect the next time the hub reloads:")
	fmt.Println("  systemctl reload acme-hub   # or: kill -HUP $(pidof acme-hub)")
	fmt.Println()

	fmt.Printf("Copy the hub's TLS certificate to %s on this spoke, and verify\n", *hubTLSCertFile)
	fmt.Println("its SHA-256 fingerprint matches what the hub logged on its own startup")
	fmt.Println("(\"hub TLS certificate ready sha256_fingerprint=...\") before trusting it.")
	fmt.Println()

	if *spokeConfigOut != "" {
		if err := os.WriteFile(*spokeConfigOut, []byte(result.SpokeConfigYAML), 0o644); err != nil {
			return fmt.Errorf("write spoke config: %w", err)
		}
		fmt.Printf("Wrote this spoke's config.yaml to %s\n", *spokeConfigOut)
	} else {
		fmt.Println("=== This spoke's config.yaml ===")
		fmt.Print(result.SpokeConfigYAML)
	}
	fmt.Println()

	fmt.Println("=== Add to this spoke's acme-spoke.env ===")
	fmt.Printf("HUB_TOKEN=%s\n", result.Token)

	return nil
}
