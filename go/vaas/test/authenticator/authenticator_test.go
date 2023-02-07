package authenticator_test

import (
	"log"
	"testing"

	"vaas/pkg/authenticator"
	utilities "vaas/test/test_utilities"


	"github.com/joho/godotenv"
)

func TestGetToken_WithValidCredentials_GotToken(t *testing.T) {
	if err := godotenv.Load(); err != nil {
		log.Println(err)
	}

	CLIENT_ID, CLIENT_SECRET, TOKEN_ENDPOINT := utilities.ReadCredentials()

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

	_, _, TOKEN_ENDPOINT := utilities.ReadCredentials()

	authenticator := authenticator.New("foo", "bar", TOKEN_ENDPOINT)
	var accessToken string
	err := authenticator.GetToken(&accessToken)
	if err == nil{
		t.Fatalf(`GetToken(&accessToken) = %q, expected "accesstoken is null"`, err)
	}
}