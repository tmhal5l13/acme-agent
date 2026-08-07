package acmeclient

import (
	"errors"
	"fmt"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"

	"acme-agent/internal/store"
)

// GetOrRegisterAccount loads the persisted ACME account for caDirectoryURL,
// or registers a fresh one (generating a new EC256 account key) if none
// exists yet.
//
// Accounts are scoped per CA directory URL because Let's Encrypt staging and
// production are separate ACME servers with separate account databases —
// an account registered against one is unknown to the other.
func GetOrRegisterAccount(st *store.Store, caDirectoryURL, email string) (*User, error) {
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
		return registerAccount(st, caDirectoryURL, email)

	default:
		return nil, fmt.Errorf("load account: %w", err)
	}
}

func registerAccount(st *store.Store, caDirectoryURL, email string) (*User, error) {
	privKey, err := certcrypto.GeneratePrivateKey(certcrypto.EC256)
	if err != nil {
		return nil, fmt.Errorf("generate account key: %w", err)
	}

	user := &User{Email: email, PrivateKey: privKey}

	cfg := lego.NewConfig(user)
	cfg.CADirURL = caDirectoryURL

	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("create ACME client: %w", err)
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, fmt.Errorf("register ACME account: %w", err)
	}
	user.Registration = reg

	if err := st.SaveAccount(&store.Account{
		CADirectoryURL:  caDirectoryURL,
		Email:           email,
		PrivateKeyPEM:   string(certcrypto.PEMEncode(privKey)),
		RegistrationURI: reg.URI,
	}); err != nil {
		return nil, fmt.Errorf("save account: %w", err)
	}

	return user, nil
}
