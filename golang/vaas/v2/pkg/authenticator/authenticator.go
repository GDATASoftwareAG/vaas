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

	"net/http"
	"net/url"
	"time"

	msg "github.com/GDATASoftwareAG/vaas/golang/vaas/v2/pkg/messages"
)

// Authenticator represents the interface for obtaining an authentication token using client credentials.
type Authenticator interface {
	GetToken() (string, error)
}

// clientCredentialsGrantAuthenticator is an implementation of the Authenticator interface.
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
func New(clientID string, clientSecret string, tokenEndpoint string) Authenticator {
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
func NewWithDefaultTokenEndpoint(clientID string, clientSecret string) Authenticator {
	return &clientCredentialsGrantAuthenticator{
		clientID:      clientID,
		clientSecret:  clientSecret,
		tokenEndpoint: "https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token",
		httpClient:    &http.Client{Timeout: 120 * time.Second},
	}
}

// GetToken obtains an authentication token using the clientCredentialsGrantAuthenticator.
// It returns the obtained token and any error encountered during the process.
func (c clientCredentialsGrantAuthenticator) GetToken() (string, error) {
	// TODO: Memoize token until expiration (see C++), thread-safety
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

// resourceOwnerPasswordGrantAuthenticator is an implementation of the Authenticator interface
// that obtains an authentication token using the resource owner password grant.
type resourceOwnerPasswordGrantAuthenticator struct {
	httpClient    *http.Client
	clientID      string
	username      string
	password      string
	tokenEndpoint string
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
	return &resourceOwnerPasswordGrantAuthenticator{
		clientID:      clientID,
		username:      username,
		password:      password,
		tokenEndpoint: tokenEndpoint,
		httpClient:    &http.Client{Timeout: 120 * time.Second},
	}
}

// GetToken obtains an authentication token using the resourceOwnerPasswordGrantAuthenticator.
// It returns the obtained token and any error encountered during the process.
func (c resourceOwnerPasswordGrantAuthenticator) GetToken() (string, error) {
	// TODO: Memoize token until expiration (see C++), thread-safety
	data := url.Values{}
	data.Set("client_id", c.clientID)
	data.Set("username", c.username)
	data.Set("password", c.password)
	data.Set("grant_type", "password")

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
