package vaas

import (
	"errors"
	"net/url"
	"sync"
	"time"

	msg "vaas/pkg/messages"
	"vaas/pkg/options"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

const TIMEOUT = 60

type Vaas struct {
	sessionId           string
	websocketConnection *websocket.Conn
	Url                 url.URL `default:"wss://gateway-vaas.gdatasecurity.de"`
	options             options.VaasOptions
	writeLock           sync.Mutex
	readLock            sync.Mutex
}

func New(options options.VaasOptions) *Vaas {
	vaas := &Vaas{options: options}
	return vaas
}

func (v *Vaas) Connect(token string) <-chan error {
	channel := make(chan error)

	go func() {
		connection, _, websocketErr := websocket.DefaultDialer.Dial("wss://gateway-vaas.gdatasecurity.de", nil)
		if websocketErr != nil {
			channel <- websocketErr
		}

		v.websocketConnection = connection

		err := <-v.Authenticate(token)
		if err != nil {
			channel <- errors.New("failed to authenticate: " + err.Error())
		}
		channel <- nil
	}()

	return channel
}

func (v *Vaas) Authenticate(token string) <-chan error {
	channel := make(chan error)

	go func() {
		v.websocketConnection.WriteJSON(msg.AuthRequest{
			Kind:  "AuthRequest",
			Token: token,
		})

		var authResponse msg.AuthResponse
		v.websocketConnection.ReadJSON(&authResponse)
		if authResponse.Kind == "Error" {
			channel <- errors.New(authResponse.Text)
		}
		if !authResponse.Success {
			channel <- errors.New("failed to authenticate")
		}

		v.sessionId = authResponse.SessionId
		channel <- nil
	}()

	return channel
}

func (v *Vaas) ForSha256(sha256 string) (msg.VaasVerdict, error) {
	if v.sessionId == "" {
		return msg.VaasVerdict{}, errors.New("invalid operation")
	}

	verdict, err := v.ForSha256List([]string{sha256})
	if err != nil {
		return msg.VaasVerdict{}, err
	}

	return verdict[0], nil
}

func (v *Vaas) ForSha256List(sha256List []string) ([]msg.VaasVerdict, error) {
	if v.sessionId == "" {
		return []msg.VaasVerdict{}, errors.New("invalid operation")
	}

	var verdicts []msg.VaasVerdict
	var sentSha256Counter int
	var writerGroup sync.WaitGroup
	var readerGroup sync.WaitGroup

	for _, sha256 := range sha256List {
		writerGroup.Add(1)
		go func(sha256 string) {
			defer writerGroup.Done()
			request := msg.VerdictRequest{
				Kind:      "VerdictRequest",
				Sha256:    sha256,
				SessionID: v.sessionId,
				Guid:      uuid.New().String(),
				UseCache:  false,
				UseShed:   true,
			}
			if err := v.forRequest(request); err != nil {
				verdicts = append(verdicts, msg.VaasVerdict{
					Sha256:  sha256,
					Verdict: msg.Verdict(msg.Error),
				})
			} else {
				sentSha256Counter++
			}
		}(sha256)
	}
	writerGroup.Wait()

	verdicts = v.waitForResponses(sentSha256Counter, &readerGroup)

	return verdicts, nil
}

func (v *Vaas) waitForResponses(expectedResponses int, readerGroup *sync.WaitGroup) []msg.VaasVerdict {
	var verdicts []msg.VaasVerdict

	for i := 0; i < expectedResponses; i++ {
		readerGroup.Add(1)
		go func() {
			defer readerGroup.Done()
			v.websocketConnection.SetReadDeadline(time.Now().Add(TIMEOUT * time.Second))
			if response, err := v.forResponse(); err != nil {
				verdicts = append(verdicts, msg.VaasVerdict{Verdict: msg.Verdict(msg.Error)})
			} else {
				verdicts = append(verdicts, msg.VaasVerdict{
					Verdict: response.Verdict,
					Sha256:  response.Sha256,
				})
			}
		}()
	}

	readerGroup.Wait()
	return verdicts
}

func (v *Vaas) forRequest(verdictRequest msg.VerdictRequest) error {
	defer v.writeLock.Unlock()
	v.writeLock.Lock()
	return v.websocketConnection.WriteJSON(verdictRequest)
}

func (v *Vaas) forResponse() (msg.VerdictResponse, error) {
	defer v.readLock.Unlock()
	v.readLock.Lock()

	var verdictResponse msg.VerdictResponse
	if err := v.websocketConnection.ReadJSON(&verdictResponse); err != nil {
		return msg.VerdictResponse{}, err
	}

	if verdictResponse.IsValid() {
		return verdictResponse, nil
	} else {
		return msg.VerdictResponse{}, errors.New("invalid response")
	}
}
