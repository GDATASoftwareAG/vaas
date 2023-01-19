package vaas

import (
	"crypto/sha256"
	"encoding/json"
	"io"
	"log"
	"net/url"
	"os"

	msg "vaas/pkg/messages"

	"github.com/gorilla/websocket"
)

type Vaas struct {
	sessionId           string
	websocketConnection *websocket.Conn
	Url                 url.URL `default:"wss://gateway-vaas.gdatasecurity.de"`
	options             VaasOptions
}

func New(options VaasOptions) *Vaas {
	vaas := &Vaas{options: options}
	return vaas
}

func (v *Vaas) Connect(token string, url string) error {
	connection, _, websocketErr := websocket.DefaultDialer.Dial(url, nil)
	if websocketErr != nil {
		log.Println("Could not start client")
		return websocketErr
	}

	v.websocketConnection = connection
	v.Authenticate(token)
	var authResponse msg.AuthResponse
	v.websocketConnection.ReadJSON(authResponse)
	v.sessionId = authResponse.SessionId

	return nil
}

func (v Vaas) Authenticate(token string) error {
	var authenticationRequest, marshalErr = json.Marshal(msg.AuthRequest{
		Token: token,
	})
	if marshalErr != nil {
		log.Fatalf("%v", marshalErr)
		return marshalErr
	}

	v.websocketConnection.WriteJSON(authenticationRequest)

	return nil
}

func (v Vaas) ForFile(path string) (msg.VaasVerdict, error) {
	file, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	sha256 := sha256.New()
	if _, err := io.Copy(sha256, file); err != nil {
		log.Fatal(err)
	}

	if v.sessionId == "" {
		log.Fatal("invalid operation")
	}

	v.forRequest(msg.VerdictRequest{
		Sha256:   sha256,
		UseCache: v.options.UseCache,
		UseShed:  v.options.UseShed,
	})
	var verdict msg.VaasVerdict

	return verdict, nil
}

func (v Vaas) forRequest(verdictRequest msg.VerdictRequest) msg.VerdictResponse {
	v.websocketConnection.WriteJSON(verdictRequest)
	var verdictResponse msg.VerdictResponse
	v.websocketConnection.ReadJSON(verdictResponse)

	return verdictResponse
}
