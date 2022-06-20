package vaas

import (
	"encoding/json"
	"log"
	"vaas/src/messages"

	"github.com/gorilla/websocket"
)

type VaaS struct {
	sessionId       string
	websocketClient *websocket.Conn
}

func (vaas VaaS) Connect(token string, url string) error {
	client, _, websocketErr := websocket.DefaultDialer.Dial(url, nil)
	if websocketErr != nil {
		log.Println("Error occured while creating a websocket client")
		return websocketErr
	}

	vaas.websocketClient = client
	vaas.Authenticate(token)
	client.ReadJSON()

	return nil
}

func (vaas VaaS) Authenticate(token string) error {
	var authenticationRequest, marshalErr = json.Marshal(messages.AuthRequest{
		Kind:      "auth_request",
		Token:     token,
		SessionId: "",
	})
	if marshalErr != nil {
		log.Fatalf("%v", marshalErr)
		return marshalErr
	}

	vaas.websocketClient.WriteJSON(authenticationRequest)

	return nil
}
