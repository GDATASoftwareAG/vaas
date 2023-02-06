package authenticator

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	msg "vaas/pkg/messages"
)

type IClientCredentialsGrantAuthenticator interface {
	GetToken(accessToken *string) error
}

type ClientCredentialsGrantAuthenticator struct {
	cliendId      string
	clientSecret  string
	tokenEndpoint string
	httpClient    *http.Client
}

func New(clientId string, clientSecret string, tokenEndpoint string) *ClientCredentialsGrantAuthenticator {
	return &ClientCredentialsGrantAuthenticator{
		cliendId:      clientId,
		clientSecret:  clientSecret,
		tokenEndpoint: tokenEndpoint,
		httpClient:    &http.Client{Timeout: 2 * time.Second},
	}
}

func (c ClientCredentialsGrantAuthenticator) GetToken(accessToken *string) error {
	channel := make(chan error)

	go func() {
		data := url.Values{}
		data.Set("client_id", c.cliendId)
		data.Set("client_secret", c.clientSecret)
		data.Set("grant_type", "client_credentials")

		request, err := http.NewRequest("POST", c.tokenEndpoint, bytes.NewReader([]byte(data.Encode())))
		if err != nil {
			channel <- err
		}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		response, err := c.httpClient.Do(request)
		if err != nil {
			channel <- err
		}

		var tokenResponse msg.TokenResponse
		if json.NewDecoder(response.Body).Decode(&tokenResponse); err != nil {
			channel <- err
		}

		*accessToken = tokenResponse.Accesstoken
		channel <- nil
	}()

	return <-channel
}
