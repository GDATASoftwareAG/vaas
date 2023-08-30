// Package authenticator provides an authentication client for G DATA CyberDefense's VaaS.
package authenticator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	msg "github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/messages"
)

// ClientCredentialsGrantAuthenticator represents the interface for obtaining an authentication token using client credentials.
type ClientCredentialsGrantAuthenticator interface {
	GetToken() (string, error)
}

// clientCredentialsGrantAuthenticator is an implementation of the ClientCredentialsGrantAuthenticator interface.
type clientCredentialsGrantAuthenticator struct {
	httpClient    *http.Client
	clientID      string
	clientSecret  string
	tokenEndpoint string
}

// New creates a new instance of the clientCredentialsGrantAuthenticator.
// It requires the client ID, client secret, and token endpoint URL as arguments.
// Example usage:
//
//	clientID := "your-client-id"
//	clientSecret := "your-client-secret"
//	tokenEndpoint := "https://example.com/token-endpoint"
//
//	auth := authenticator.New(clientID, clientSecret, tokenEndpoint)
//	token, err := auth.GetToken()
//	if err != nil {
//	    log.Fatal(err)
//	}
func New(clientID string, clientSecret string, tokenEndpoint string) ClientCredentialsGrantAuthenticator {
	return &clientCredentialsGrantAuthenticator{
		clientID:      clientID,
		clientSecret:  clientSecret,
		tokenEndpoint: tokenEndpoint,
		httpClient:    &http.Client{Timeout: 120 * time.Second},
	}
}

// NewWithDefaultTokenEndpoint creates a new instance of the clientCredentialsGrantAuthenticator with a default token endpoint.
// It requires the client ID and client secret as arguments.
// Example usage:
//
//	clientID := "your-client-id"
//	clientSecret := "your-client-secret"
//	tokenEndpoint := "https://example.com/token-endpoint"
//
//	auth := authenticator.NewWithDefaultTokenEndpoint(clientID, clientSecret)
//	token, err := auth.GetToken()
//	if err != nil {
//	    log.Fatal(err)
//	}
func NewWithDefaultTokenEndpoint(clientID string, clientSecret string) ClientCredentialsGrantAuthenticator {
	return &clientCredentialsGrantAuthenticator{
		clientID:      clientID,
		clientSecret:  clientSecret,
		tokenEndpoint: "https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token",
		httpClient:    &http.Client{Timeout: 120 * time.Second},
	}
}

// GetToken obtains an authentication token using the client credentials grant.
// It returns the obtained token and any error encountered during the process.
func (c clientCredentialsGrantAuthenticator) GetToken() (string, error) {
	data := url.Values{}
	data.Set("client_id", c.clientID)
	data.Set("client_secret", c.clientSecret)
	data.Set("grant_type", "client_credentials")

	request, err := http.NewRequest("POST", c.tokenEndpoint, bytes.NewReader([]byte(data.Encode())))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := c.httpClient.Do(request)
	if err != nil {
		return "", err
	}

	if response.StatusCode != 200 {
		return "", fmt.Errorf("http request failed: %s", response.Status)
	}

	var tokenResponse msg.TokenResponse
	if err = json.NewDecoder(response.Body).Decode(&tokenResponse); err != nil {
		return "", err
	}

	return tokenResponse.Accesstoken, nil
}
