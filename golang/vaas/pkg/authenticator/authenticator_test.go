package authenticator

import (
	"log"
	"testing"

	credentials "vaas/pkg/credentials"

	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
)

func TestGetToken_WithValidCredentials_GotToken(t *testing.T) {
	if err := godotenv.Load(); err != nil {
		log.Println(err)
	}

	CLIENT_ID, CLIENT_SECRET, _, TOKEN_ENDPOINT := credentials.ReadCredentials()
	authenticator := New(CLIENT_ID, CLIENT_SECRET, TOKEN_ENDPOINT)
	var accessToken string

	err := authenticator.GetToken(&accessToken)
	if err != nil {
		t.Fatal(err)
	}

	assert.NotEmpty(t, accessToken)
}

func TestGetToken_WithWrongCredentials_Error(t *testing.T) {
	if err := godotenv.Load(); err != nil {
		log.Fatal(err)
	}

	_, _, _, TOKEN_ENDPOINT := credentials.ReadCredentials()

	authenticator := New("foo", "bar", TOKEN_ENDPOINT)
	var accessToken string
	err := authenticator.GetToken(&accessToken)

	assert.NotEqual(t, err, nil)
	assert.Empty(t, accessToken)
}
