// Package credentials provides utility functions for reading client credentials and endpoints from environment variables.
package credentials

import (
	"log"
	"os"
)

// ReadCredentials reads client credentials and endpoint URLs from environment variables.
// It returns the client ID, client secret, VaaS endpoint URL, and token endpoint URL.
func ReadCredentials() (client_id string, client_secret string, vaas_url string, token_url string) {
	ci, exists := os.LookupEnv("CLIENT_ID")
	if !exists {
		log.Fatal("no Client ID set")
	}
	cs, exists := os.LookupEnv("CLIENT_SECRET")
	if !exists {
		log.Fatal("no Client Secret set")
	}
	vu, exists := os.LookupEnv("VAAS_URL")
	if !exists {
		log.Fatal("no vaas endpoint configured")
	}
	te, exists := os.LookupEnv("TOKEN_URL")
	if !exists {
		log.Fatal("no token endpoint configured")
	}

	return ci, cs, vu, te
}
