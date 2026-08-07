// Command acme-onboard generates the matching hub-config snippet and spoke
// config.yaml needed to add one certificate to one spoke. It never edits
// any file itself (except optionally writing the new spoke's config.yaml
// to a path you give it) — it only prints what to paste where, after
// validating the request against the hub's real, current config.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"acme-agent/config"
	"acme-agent/internal/onboard"
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
	hubTLSCertFile := flag.String("hub-tls-cert-file", "/etc/acme-client/hub-cert.pem", "local path, on this new spoke, where you'll copy the hub's certificate to")
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

	var domainList []string
	for _, d := range strings.Split(*domains, ",") {
		if d = strings.TrimSpace(d); d != "" {
			domainList = append(domainList, d)
		}
	}

	result, err := onboard.Plan(hubCfg, onboard.Request{
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

	fmt.Println("=== Add to the hub's config.yaml, under `spokes:` ===")
	fmt.Print(result.HubConfigYAML)
	fmt.Println()

	if result.IsNewSpoke {
		fmt.Println("=== Add to the hub's acme-hub.env ===")
		fmt.Printf("%s=%s\n", result.HubEnvVarName, result.Token)
	} else {
		fmt.Println("(existing spoke — its token in acme-hub.env is unchanged)")
	}
	fmt.Println()
	fmt.Println("Restart the hub after editing its config — no hot-reload.")
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

	fmt.Println("=== Add to this spoke's acme-client.env ===")
	fmt.Printf("HUB_TOKEN=%s\n", result.Token)

	return nil
}
