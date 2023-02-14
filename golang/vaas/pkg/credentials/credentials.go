package credentials

import (
	"log"
	"os"
)

func ReadCredentials() (CLIENT_ID string, CLIENT_SECRET string, VAAS_URL string, TOKEN_ENDPOINT string) {
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
		log.Fatal("no token endpoint configured")
	}
	te, exists := os.LookupEnv("TOKEN_ENDPOINT")
	if !exists {
		log.Fatal("no token endpoint configured")
	}

	return ci, cs, vu, te
}
