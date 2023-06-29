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

type ClientCredentialsGrantAuthenticator interface {
	GetToken() (string, error)
}

type clientCredentialsGrantAuthenticator struct {
	httpClient    *http.Client
	cliendId      string
	clientSecret  string
	tokenEndpoint string
}

func New(clientId string, clientSecret string, tokenEndpoint string) ClientCredentialsGrantAuthenticator {
	return &clientCredentialsGrantAuthenticator{
		cliendId:      clientId,
		clientSecret:  clientSecret,
		tokenEndpoint: tokenEndpoint,
		httpClient:    &http.Client{Timeout: 120 * time.Second},
	}
}

func NewWithDefaultTokenEndpoint(clientId string, clientSecret string) ClientCredentialsGrantAuthenticator {
	return &clientCredentialsGrantAuthenticator{
		cliendId:      clientId,
		clientSecret:  clientSecret,
		tokenEndpoint: "https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token",
		httpClient:    &http.Client{Timeout: 120 * time.Second},
	}
}

func (c clientCredentialsGrantAuthenticator) GetToken() (string, error) {
	data := url.Values{}
	data.Set("client_id", c.cliendId)
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
