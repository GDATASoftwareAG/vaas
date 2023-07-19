package credentials

import (
	"log"
	"os"
)

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
