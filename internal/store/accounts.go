package store

import "database/sql"

// Account is a persisted ACME account: its identity, its account key (not a
// certificate key), and where it's registered.
type Account struct {
	CADirectoryURL  string
	Email           string
	PrivateKeyPEM   string
	RegistrationURI string
}

// GetAccount returns the account registered against caDirectoryURL, or
// ErrNotFound if none has been registered yet.
func (s *Store) GetAccount(caDirectoryURL string) (*Account, error) {
	row := s.db.QueryRow(`
		SELECT ca_directory_url, email, private_key_pem, registration_uri
		FROM acme_accounts WHERE ca_directory_url = ?`, caDirectoryURL)

	var a Account
	var regURI sql.NullString
	err := row.Scan(&a.CADirectoryURL, &a.Email, &a.PrivateKeyPEM, &regURI)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	a.RegistrationURI = regURI.String
	return &a, nil
}

// SaveAccount persists a newly registered account.
func (s *Store) SaveAccount(a *Account) error {
	_, err := s.db.Exec(`
		INSERT INTO acme_accounts (ca_directory_url, email, private_key_pem, registration_uri)
		VALUES (?, ?, ?, ?)`,
		a.CADirectoryURL, a.Email, a.PrivateKeyPEM, a.RegistrationURI)
	return err
}
