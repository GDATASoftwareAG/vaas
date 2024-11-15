// Package authenticator provides a set of implementations for obtaining authentication tokens
// for G DATA CyberDefense's Verdict as a Service (VaaS) using different grant types.
//
// # Overview
//
// VaaS (Verdict as a Service) is a service that allows clients to obtain verdicts and security information
// about files and URLs. To access VaaS, clients need to authenticate themselves by obtaining an access token.
//
// This package offers two primary implementations of the Authenticator interface:
//
//  1. clientCredentialsGrantAuthenticator: This implementation follows the Client Credentials Grant flow,
//     suitable for machine-to-machine communication where the client directly authenticates with its credentials.
//     To use this grant type, you need a client ID and a client secret.
//
//  2. resourceOwnerPasswordGrantAuthenticator: This implementation follows the Resource Owner Password Grant flow,
//     suitable for scenarios where the client has access to the user's credentials and can authenticate on their behalf.
//     To use this grant type, you need a client ID, username, and password.
//
// # Usage
//
// To use this package, you typically follow these steps:
//
// 1. Choose the appropriate grant type based on your use case:
//   - Use `New` or `NewWithDefaultTokenEndpoint` for the Client Credentials Grant.
//   - Use `NewWithResourceOwnerPassword` for the Resource Owner Password Grant.
//
// 2. Initialize an authenticator with the required parameters, such as client ID, client secret, username, and password.
//
// 3. Call the `GetToken` method to obtain an authentication token.
//
// Example:
//
//	clientID := "your-client-id"
//	clientSecret := "your-client-secret"
//	tokenEndpoint := "https://example.com/token-endpoint"
//
//	// Create an authenticator for the Client Credentials Grant
//	auth := authenticator.New(clientID, clientSecret, tokenEndpoint)
//
//	// Obtain an authentication token
//	token, err := auth.GetToken()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Use the obtained token for accessing VaaS services.
//
// Note: Make sure to keep your client credentials secure, and use the appropriate grant type for your use case.
//
// For more information about VaaS and the different grant types, refer to the official G DATA CyberDefense VaaS documentation.
package authenticator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"

	"net/http"
	"net/url"
	"time"

	msg "github.com/GDATASoftwareAG/vaas/golang/vaas/v2/pkg/messages"
)

// Authenticator represents the interface for obtaining an authentication token using client credentials.
type Authenticator interface {
	GetToken() (string, error)
}

// commonOIDCAuthenticator implements the Authenticator, supporting both the clientCredentials and
// resourceOwnerPassword flows.
type commonOIDCAuthenticator struct {
	httpClient    *http.Client
	tokenEndpoint string
	parameters    url.Values
	token         *cachedToken
	tokenLock     sync.Mutex
}

// cachedToken is a cached access token that may be reused
type cachedToken struct {
	accessToken string
	expires     time.Time
}

// ShouldRefresh determines whether this token should be replaced by a newer one
func (c cachedToken) ShouldRefresh() bool {
	// Suggest refreshing the token slightly early to avoid races
	return time.Now().Add(time.Minute).After(c.expires)
}

func parametersForClientCredentials(clientID, clientSecret string) url.Values {
	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("grant_type", "client_credentials")
	return data
}

func parametersForResourceOwnerPassword(clientID, username, password string) url.Values {
	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("username", username)
	data.Set("password", password)
	data.Set("grant_type", "password")
	return data
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
func New(clientID string, clientSecret string, tokenEndpoint string) Authenticator {
	return &commonOIDCAuthenticator{
		tokenEndpoint: tokenEndpoint,
		httpClient:    &http.Client{Timeout: 120 * time.Second},
		parameters:    parametersForClientCredentials(clientID, clientSecret),
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
func NewWithDefaultTokenEndpoint(clientID string, clientSecret string) Authenticator {
	return New(clientID, clientSecret, "https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token")
}

// GetToken obtains an authentication token using the configured authentication flow.
// It returns the obtained token and any error encountered during the process.
func (c *commonOIDCAuthenticator) GetToken() (string, error) {
	c.tokenLock.Lock()
	defer c.tokenLock.Unlock()

	if c.token == nil || c.token.ShouldRefresh() {
		// New token
		response, err := c.httpClient.Post(c.tokenEndpoint, "application/x-www-form-urlencoded", bytes.NewReader([]byte(c.parameters.Encode())))
		if err != nil {
			return "", err
		}

		if response.StatusCode != 200 {
			var tokenErrResponse msg.TokenErrorResponse
			if err := json.NewDecoder(response.Body).Decode(&tokenErrResponse); err != nil {
				return "", fmt.Errorf("http request failed: %s", response.Status)
			}
			return "", fmt.Errorf(tokenErrResponse.Error + ": " + tokenErrResponse.ErrorDescription)
		}

		var tokenResponse msg.TokenResponse
		if err = json.NewDecoder(response.Body).Decode(&tokenResponse); err != nil {
			return "", err
		}

		c.token = &cachedToken{
			accessToken: tokenResponse.Accesstoken,
			expires:     time.Now().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second),
		}
	}
	return c.token.accessToken, nil
}

// NewWithResourceOwnerPassword creates a new instance of the resourceOwnerPasswordGrantAuthenticator.
// It requires the client ID, username, password, and token endpoint URL as arguments.
// Example usage:
//
// clientID := "your-client-id"
// username := "your-username"
// password := "your-password"
// tokenEndpoint := "https://example.com/token-endpoint"
//
// auth := authenticator.NewWithResourceOwnerPassword(clientID, username, password, tokenEndpoint)
// token, err := auth.GetToken()
//
//	if err != nil {
//	    log.Fatal(err)
//	}
func NewWithResourceOwnerPassword(clientID string, username string, password string, tokenEndpoint string) Authenticator {
	return &commonOIDCAuthenticator{
		tokenEndpoint: tokenEndpoint,
		httpClient:    &http.Client{Timeout: 120 * time.Second},
		parameters:    parametersForResourceOwnerPassword(clientID, username, password),
	}
}
