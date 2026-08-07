// Package acmeclient wraps the lego ACME library: account registration and
// certificate issuance.
package acmeclient

import (
	"crypto"

	"github.com/go-acme/lego/v4/registration"
)

// User implements lego's registration.User interface, which is how lego
// expects account identity and key material to be supplied to it.
type User struct {
	Email        string
	Registration *registration.Resource
	PrivateKey   crypto.PrivateKey
}

func (u *User) GetEmail() string                        { return u.Email }
func (u *User) GetRegistration() *registration.Resource { return u.Registration }
func (u *User) GetPrivateKey() crypto.PrivateKey        { return u.PrivateKey }
