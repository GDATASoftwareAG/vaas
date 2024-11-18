package main

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func TestDoubleMe(t *testing.T) {
	table := []struct {
		name                   string
		clientId               string
		clientSecret           string
		username               string
		password               string
		exprectedError         error
		expectedAuthrenticator string
	}{
		{"no credentials set",
			"", "", "", "",
			errors.New("you either need VAAS_CLIENT_ID and VAAS_CLIENT_SECRET or VAAS_USERAME and VAAS_PASSWORD"), "<nil>"},
		{"client_id set but client_secret empty",
			"client_id", "", "", "",
			errors.New("you either need VAAS_CLIENT_ID and VAAS_CLIENT_SECRET or VAAS_USERAME and VAAS_PASSWORD"), "<nil>"},
		{"client_secret set but client_id empty",
			"", "client_secret", "", "",
			errors.New("you either need VAAS_CLIENT_ID and VAAS_CLIENT_SECRET or VAAS_USERAME and VAAS_PASSWORD"), "<nil>"},
		{"username set but password empty",
			"", "", "username", "",
			errors.New("you either need VAAS_CLIENT_ID and VAAS_CLIENT_SECRET or VAAS_USERAME and VAAS_PASSWORD"), "<nil>"},
		{"password set but username empty",
			"", "", "", "password",
			errors.New("you either need VAAS_CLIENT_ID and VAAS_CLIENT_SECRET or VAAS_USERAME and VAAS_PASSWORD"), "<nil>"},
		{"only client_id and username set",
			"client_id", "", "username", "",
			errors.New("you either need VAAS_CLIENT_ID and VAAS_CLIENT_SECRET or VAAS_USERAME and VAAS_PASSWORD"), "<nil>"},
		{"client_credentials set",
			"client_id", "client_secret", "", "",
			nil, "*authenticator.commonOIDCAuthenticator"},
		{"client_credentials and username set",
			"client_id", "client_secret", "username", "",
			nil, "*authenticator.commonOIDCAuthenticator"},
		{"username and password set",
			"", "", "username", "password",
			nil, "*authenticator.commonOIDCAuthenticator"},
		{"username and password and	client_id set",
			"client_id", "", "username", "password",
			nil, "*authenticator.commonOIDCAuthenticator"},
	}

	for _, tc := range table {
		t.Run(tc.name, func(t *testing.T) {
			vaasAuthenticator, credentialsError := getAuthenticator(tc.clientId, tc.clientSecret, tc.username, tc.password)

			if reflect.TypeOf(credentialsError) != reflect.TypeOf(tc.exprectedError) {
				t.Errorf("Expected error to be %s, but got %s", tc.exprectedError, credentialsError)
			}

			typestring := fmt.Sprint(reflect.TypeOf(vaasAuthenticator))
			if typestring != tc.expectedAuthrenticator {
				t.Errorf("Expected type %s, but got %s", tc.expectedAuthrenticator, typestring)
			}
		})
	}
}
