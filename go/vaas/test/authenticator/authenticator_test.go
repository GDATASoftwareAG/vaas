package authenticator_test

import (
	"log"
	"os"
	"testing"

	"vaas/pkg/authenticator"

	"github.com/joho/godotenv"
)

func TestGetToken_WithValidCredentials_GotToken(t *testing.T) {
	if err := godotenv.Load(); err != nil {
		log.Println(err)
	}

	CLIENT_ID, CLIENT_SECRET, TOKEN_ENDPOINT := readCredentials()

	authenticator := authenticator.New(CLIENT_ID,CLIENT_SECRET, TOKEN_ENDPOINT)
	var accessToken string
	err := authenticator.GetToken(&accessToken)
	if accessToken == "" || err != nil {
		t.Fatalf(`GetToken(&accessToken) = %q, %v`, accessToken, err)
	}
}

func TestGetToken_WithWrongCredentials_Error(t *testing.T) {
	if err := godotenv.Load(); err != nil {
		log.Fatal(err)
	}

	_, _, TOKEN_ENDPOINT := readCredentials()

	authenticator := authenticator.New("foo", "bar", TOKEN_ENDPOINT)
	var accessToken string
	err := authenticator.GetToken(&accessToken)
	if err == nil{
		t.Fatalf(`GetToken(&accessToken) = %q, expected "accesstoken is null"`, err)
	}
}


func readCredentials() (string, string, string) {
	CLIENT_ID, exists := os.LookupEnv("CLIENT_ID")
	if !exists {
		log.Fatal("no Client ID set")
	}
	CLIENT_SECRET, exists := os.LookupEnv("CLIENT_SECRET")
	if !exists {
		log.Fatal("no Client Secret set")
	}
	TOKEN_ENDPOINT, exists := os.LookupEnv("TOKEN_ENDPOINT")
	if !exists {
		log.Fatal("no token endpoint configured")
	}
	return CLIENT_ID, CLIENT_SECRET, TOKEN_ENDPOINT
}
