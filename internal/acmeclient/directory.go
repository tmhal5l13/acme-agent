package acmeclient

import (
	"fmt"

	"github.com/go-acme/lego/v4/lego"
)

// DirectoryURL maps config's acme.environment value to the corresponding
// ACME directory URL. environment is validated by config.LoadConfig, so the
// default case here should be unreachable in practice.
func DirectoryURL(environment string) (string, error) {
	switch environment {
	case "staging":
		return lego.LEDirectoryStaging, nil
	case "production":
		return lego.LEDirectoryProduction, nil
	default:
		return "", fmt.Errorf("unknown acme environment %q", environment)
	}
}
