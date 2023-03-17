package authenticator

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"

	msg "github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/messages"
)

type ClientCredentialsGrantAuthenticator interface {
	GetToken(accessToken *string) error
}

type clientCredentialsGrantAuthenticator struct {
	cliendId      string
	clientSecret  string
	tokenEndpoint string
	httpClient    *http.Client
}

func New(clientId string, clientSecret string, tokenEndpoint string) ClientCredentialsGrantAuthenticator {
	return &clientCredentialsGrantAuthenticator{
		cliendId:      clientId,
		clientSecret:  clientSecret,
		tokenEndpoint: tokenEndpoint,
		httpClient:    &http.Client{Timeout: 120 * time.Second},
	}
}

func (c clientCredentialsGrantAuthenticator) GetToken(accessToken *string) error {
	data := url.Values{}
	data.Set("client_id", c.cliendId)
	data.Set("client_secret", c.clientSecret)
	data.Set("grant_type", "client_credentials")

	request, err := http.NewRequest("POST", c.tokenEndpoint, bytes.NewReader([]byte(data.Encode())))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := c.httpClient.Do(request)
	if err != nil {
		return err
	}

	var tokenResponse msg.TokenResponse
	if err := json.NewDecoder(response.Body).Decode(&tokenResponse); err != nil {
		return err
	}

	if tokenResponse.Accesstoken == "" {
		return errors.New("accesstoken is null")
	}

	*accessToken = tokenResponse.Accesstoken
	return nil
}
