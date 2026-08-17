package acmeclient

import (
	"errors"
	"fmt"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"

	"github.com/tmhal5l13/acme-agent/config"
	"github.com/tmhal5l13/acme-agent/internal/store"
)

// GetOrRegisterAccount loads the persisted ACME account for caDirectoryURL,
// or registers a fresh one (generating a new EC256 account key) if none
// exists yet. caDirectoryURL is resolved once by the caller (via
// DirectoryURL) rather than re-resolved here, since callers generally need
// the same URL again for Issue.
//
// Accounts are scoped per CA directory URL because separate ACME servers
// (Let's Encrypt staging vs. production, or any two different CAs) have
// separate account databases — an account registered against one is
// unknown to the other.
func GetOrRegisterAccount(st *store.Store, caDirectoryURL string, acmeCfg config.ACMEConfig) (*User, error) {
	acct, err := st.GetAccount(caDirectoryURL)
	switch {
	case err == nil:
		privKey, err := certcrypto.ParsePEMPrivateKey([]byte(acct.PrivateKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("parse stored account key: %w", err)
		}
		return &User{
			Email:        acct.Email,
			PrivateKey:   privKey,
			Registration: &registration.Resource{URI: acct.RegistrationURI},
		}, nil

	case errors.Is(err, store.ErrNotFound):
		return registerAccount(st, acmeCfg, caDirectoryURL)

	default:
		return nil, fmt.Errorf("load account: %w", err)
	}
}

func registerAccount(st *store.Store, acmeCfg config.ACMEConfig, caDirectoryURL string) (*User, error) {
	privKey, err := certcrypto.GeneratePrivateKey(certcrypto.EC256)
	if err != nil {
		return nil, fmt.Errorf("generate account key: %w", err)
	}

	user := &User{Email: acmeCfg.Email, PrivateKey: privKey}

	cfg := lego.NewConfig(user)
	cfg.CADirURL = caDirectoryURL

	httpClient, err := httpClientFor(acmeCfg)
	if err != nil {
		return nil, err
	}
	if httpClient != nil {
		cfg.HTTPClient = httpClient
	}

	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("create ACME client: %w", err)
	}

	var reg *registration.Resource
	if acmeCfg.EABKeyID != "" {
		reg, err = client.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
			TermsOfServiceAgreed: true,
			Kid:                  acmeCfg.EABKeyID,
			HmacEncoded:          acmeCfg.EABHMACKey,
		})
	} else {
		reg, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	}
	if err != nil {
		return nil, fmt.Errorf("register ACME account: %w", err)
	}
	user.Registration = reg

	if err := st.SaveAccount(&store.Account{
		CADirectoryURL:  caDirectoryURL,
		Email:           acmeCfg.Email,
		PrivateKeyPEM:   string(certcrypto.PEMEncode(privKey)),
		RegistrationURI: reg.URI,
	}); err != nil {
		return nil, fmt.Errorf("save account: %w", err)
	}

	return user, nil
}
