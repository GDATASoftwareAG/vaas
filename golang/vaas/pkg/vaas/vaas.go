package vaas

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	BroadcastChannel "vaas/pkg/broadcast_channel"
	"vaas/pkg/hash"
	msg "vaas/pkg/messages"
	"vaas/pkg/options"

	"github.com/gorilla/websocket"
)

const TIMEOUT = 60

type Vaas struct {
	sessionId           string
	websocketConnection *websocket.Conn
	broadcastChannel    *BroadcastChannel.BroadcastChannel[msg.VerdictResponse]
	requestChannel      chan msg.IVerdictRequest
	responseChannel     chan msg.VerdictResponse
	vaasUrl             string
	options             options.VaasOptions
	Ctx                 context.Context
}

func New(options options.VaasOptions, vaasUrl string) *Vaas {
	rc := make(chan msg.VerdictResponse)
	ctx := context.Background()
	bc := BroadcastChannel.New(ctx, rc)

	vaas := &Vaas{
		options:          options,
		vaasUrl:          vaasUrl,
		requestChannel:   make(chan msg.IVerdictRequest, 1),
		responseChannel:  rc,
		broadcastChannel: bc,
		Ctx:              ctx,
	}

	return vaas
}

func (v *Vaas) Connect(token string) error {
	connection, _, websocketErr := websocket.DefaultDialer.Dial(v.vaasUrl, nil)
	if websocketErr != nil {
		return websocketErr
	}
	v.websocketConnection = connection

	if err := v.Authenticate(token); err != nil {
		return errors.New("failed to authenticate: " + err.Error())
	}

	go v.sendRequests()
	go v.readResponses()

	return nil
}

func (v *Vaas) Authenticate(token string) error {
	v.websocketConnection.WriteJSON(msg.AuthRequest{
		Kind:  "AuthRequest",
		Token: token,
	})

	var authResponse msg.AuthResponse
	v.websocketConnection.ReadJSON(&authResponse)
	if authResponse.Kind == "Error" {
		return errors.New(authResponse.Text)
	}
	if !authResponse.Success {
		return errors.New("failed to authenticate")
	}

	v.sessionId = authResponse.SessionId

	return nil
}

func (v *Vaas) ForSha256(sha256 string) (msg.VaasVerdict, error) {
	if v.sessionId == "" {
		return msg.VaasVerdict{}, errors.New("invalid operation")
	}
	subscription := v.broadcastChannel.Subscribe()
	defer v.broadcastChannel.RemoveSubscription(subscription)
	request := msg.VerdictRequest{}.New(v.sessionId, v.options, sha256)
	v.requestChannel <- request

	verdictResponse, responseErr := v.waitForResponse(subscription, request.Guid)
	if responseErr != nil {
		return msg.VaasVerdict{
			Verdict: msg.Verdict(msg.Error),
			Sha256:  sha256,
		}, responseErr
	}

	return msg.VaasVerdict{
		Verdict: verdictResponse.Verdict,
		Sha256:  verdictResponse.Sha256,
	}, nil
}

func (v *Vaas) ForSha256List(sha256List []string) ([]msg.VaasVerdict, error) {
	if v.sessionId == "" {
		return []msg.VaasVerdict{}, errors.New("invalid operation")
	}

	var writerGroup sync.WaitGroup
	var verdicts []msg.VaasVerdict

	for _, sha256 := range sha256List {
		writerGroup.Add(1)
		go func(sha256 string) {
			defer writerGroup.Done()
			verdict, err := v.ForSha256(sha256)
			if err != nil {
				verdicts = append(verdicts, msg.VaasVerdict{Sha256: sha256, Verdict: msg.Verdict(msg.Error)})
				return
			}
			verdicts = append(verdicts, verdict)
		}(sha256)
	}
	writerGroup.Wait()

	return verdicts, nil
}

func (v *Vaas) ForFile(file string) (msg.VaasVerdict, error) {
	if v.sessionId == "" {
		return msg.VaasVerdict{}, errors.New("invalid operation")
	}

	data, fileErr := os.Open(file)
	if fileErr != nil {
		return msg.VaasVerdict{
			Verdict: msg.Verdict(msg.Error),
		}, fileErr

	}

	sha256, parseErr := hash.CalculateSha256(data)
	if parseErr != nil {
		return msg.VaasVerdict{
			Verdict: msg.Verdict(msg.Error),
		}, parseErr
	}

	subscription := v.broadcastChannel.Subscribe()
	defer v.broadcastChannel.RemoveSubscription(subscription)

	request := msg.VerdictRequest{}.New(v.sessionId, v.options, sha256)
	v.requestChannel <- request

	response, responseErr := v.waitForResponse(subscription, request.Guid)
	if responseErr != nil {
		return msg.VaasVerdict{
			Verdict: msg.Verdict(msg.Error),
			Sha256:  sha256,
		}, responseErr
	}

	if response.Verdict == msg.Verdict(msg.Unknown) {
		if uploadErr := v.uploadFile(data, response.Url, response.UploadToken); uploadErr != nil {
			return msg.VaasVerdict{
				Verdict: msg.Verdict(msg.Unknown),
				Sha256:  sha256,
			}, uploadErr
		} else {
			uploadResponse, responseErr := v.waitForResponse(subscription, response.Guid)
			if responseErr != nil {
				return msg.VaasVerdict{
					Verdict: msg.Verdict(msg.Error),
					Sha256:  sha256,
				}, responseErr
			} else {
				response = uploadResponse
			}
		}
	}

	return msg.VaasVerdict{
		Verdict: response.Verdict,
		Sha256:  response.Sha256,
	}, nil
}

func (v *Vaas) ForFileList(fileList []string) ([]msg.VaasVerdict, error) {
	if v.sessionId == "" {
		return []msg.VaasVerdict{}, errors.New("invalid operation")
	}

	var waitGroup sync.WaitGroup
	var verdicts []msg.VaasVerdict

	for _, file := range fileList {
		waitGroup.Add(1)

		go func(file string) {
			defer waitGroup.Done()
			verdict, err := v.ForFile(file)
			if err != nil {
				verdicts = append(verdicts, msg.VaasVerdict{Sha256: verdict.Sha256, Verdict: msg.Verdict(msg.Error)})
			} else {
				verdicts = append(verdicts, verdict)
			}
		}(file)

		waitGroup.Wait()
	}
	return verdicts, nil
}

func (v *Vaas) ForUrl(url string) (msg.VaasVerdict, error) {
	if v.sessionId == "" {
		return msg.VaasVerdict{}, errors.New("invalid operation")
	}
	subscription := v.broadcastChannel.Subscribe()
	defer v.broadcastChannel.RemoveSubscription(subscription)
	request := msg.VerdictRequestForUrl{}.New(v.sessionId, v.options, url)
	v.requestChannel <- request

	verdictResponse, responseErr := v.waitForResponse(subscription, request.Guid)
	if responseErr != nil {
		return msg.VaasVerdict{
			Verdict: msg.Verdict(msg.Error),
		}, responseErr
	}

	return msg.VaasVerdict{
		Verdict: verdictResponse.Verdict,
		Sha256:  verdictResponse.Sha256,
	}, nil
}

func (v *Vaas) uploadFile(file *os.File, url string, token string) error {
	httpClient := &http.Client{}
	file.Seek(0, 0)
	info, _ := file.Stat()
	req, err := http.NewRequest(http.MethodPut, url, file)
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", token)
	req.ContentLength = int64(info.Size())

	httpResponse, err := httpClient.Do(req)
	if err != nil {
		return err
	}

	if httpResponse.StatusCode != 200 {
		return errors.New("StatusCode:" + fmt.Sprintf("%x", httpResponse.StatusCode))
	}

	return nil
}

func (v *Vaas) waitForResponse(subscription <-chan msg.VerdictResponse, guid string) (msg.VerdictResponse, error) {
	var verdictResponse msg.VerdictResponse

	for {
		select {
		case response := <-subscription:
			if response.Guid == guid {
				verdictResponse = response
				return verdictResponse, nil
			}
		case <-time.After(TIMEOUT * time.Second):
			return verdictResponse, errors.New("timeout while waiting for response")
		}
	}
}

func (v *Vaas) sendRequests() {
	for {
		select {
		case <-v.Ctx.Done():
			return
		case request := <-v.requestChannel:
			v.websocketConnection.WriteJSON(request)
		}
	}
}

func (v *Vaas) readResponses() {
	responseChan := make(chan msg.VerdictResponse, 1)

	go func() {
		for {
			var verdictResponse msg.VerdictResponse

			if err := v.websocketConnection.ReadJSON(&verdictResponse); err != nil {
				log.Fatal(err)
				close(responseChan)
			}

			if !verdictResponse.IsValid() {
				log.Fatal("invalid response")
				close(responseChan)
			}

			responseChan <- verdictResponse
		}
	}()

	for {
		select {
		case <-v.Ctx.Done():
			v.websocketConnection.Close()
			return
		case response := <-responseChan:
			v.responseChannel <- response
		}
	}
}
