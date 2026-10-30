package platform

import (
	"database/sql"
	"errors"
	"os"
	"strings"

	"github.com/cazocarma/rac-user-service/internal/identity"
	"github.com/cazocarma/rac-user-service/internal/identity/fake"
)

// IdentityFromEnvironment returns nil when no provider is selected, so the
// identity endpoints answer unavailable instead of inventing a result. The
// real provider remains DECISION_REQUIRED (D05); only the DEV fake exists.
func IdentityFromEnvironment(db *sql.DB) (*identity.Service, error) {
	name := os.Getenv("IDENTITY_PROVIDER")
	if name == "" {
		return nil, nil
	}
	if name != "fake" {
		return nil, errors.New("unsupported identity provider")
	}
	secret, err := secretFile("IDENTITY_WEBHOOK_SECRET_FILE")
	if err != nil {
		return nil, err
	}
	key, err := secretFile("IDENTITY_FINGERPRINT_KEY_FILE")
	if err != nil {
		return nil, err
	}
	provider, err := fake.New(os.Getenv("RAC_ENV"), secret, os.Getenv("IDENTITY_FAKE_BASE_URL"))
	if err != nil {
		return nil, err
	}
	fingerprint, err := identity.NewFingerprinter(os.Getenv("IDENTITY_FINGERPRINT_KEY_ID"), key)
	if err != nil {
		return nil, err
	}
	return identity.NewService(db, provider, fingerprint)
}

func secretFile(variable string) ([]byte, error) {
	path := os.Getenv(variable)
	if path == "" {
		return nil, errors.New(variable + " is required")
	}
	value, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New(variable + " is unreadable")
	}
	return []byte(strings.TrimSpace(string(value))), nil
}
