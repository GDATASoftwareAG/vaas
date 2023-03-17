package vaas

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	broadcast "github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/broadcast"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/hash"
	msg "github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/messages"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/options"

	"github.com/gorilla/websocket"
)

const TIMEOUT = 180

type Vaas interface {
	Connect(token string) error
	Authenticate(token string) error
	ForUrl(uri string) (msg.VaasVerdict, error)
	ForSha256(sha256 string) (msg.VaasVerdict, error)
	ForFile(path string) (msg.VaasVerdict, error)
	ForFileInMemory(file io.Reader) (msg.VaasVerdict, error)
	ForSha256List(sha256List []string) ([]msg.VaasVerdict, error)
	ForFileList(fileList []string) ([]msg.VaasVerdict, error)
}

type vaas struct {
	sessionId           string
	websocketConnection *websocket.Conn
	broadcastChannel    broadcast.Channel[msg.VerdictResponse]
	requestChannel      chan msg.VerdictRequest
	responseChannel     chan msg.VerdictResponse
	vaasUrl             string
	options             options.VaasOptions
	Ctx                 context.Context
}

func New(options options.VaasOptions, vaasUrl string) Vaas {
	rc := make(chan msg.VerdictResponse)

	vaas := &vaas{
		options:         options,
		vaasUrl:         vaasUrl,
		requestChannel:  make(chan msg.VerdictRequest, 1),
		responseChannel: rc,
	}

	return vaas
}

func (v *vaas) setBroadcastChannel(broadcastChannel broadcast.Channel[msg.VerdictResponse]) {
	v.broadcastChannel = broadcastChannel
}

func (v *vaas) Connect(token string) error {
	connection, _, err := websocket.DefaultDialer.Dial(v.vaasUrl, nil)
	if err != nil {
		return err
	}
	v.websocketConnection = connection

	if err := v.Authenticate(token); err != nil {
		return errors.New("failed to authenticate: " + err.Error())
	}
	ctx := context.Background()
	v.setBroadcastChannel(broadcast.New(ctx, v.responseChannel))
	go v.sendRequests(ctx)
	go v.readResponses(ctx)

	return nil
}

func (v *vaas) Authenticate(token string) error {
	if err := v.websocketConnection.WriteJSON(msg.AuthRequest{
		Kind:  "AuthRequest",
		Token: token,
	}); err != nil {
		return err
	}

	var authResponse msg.AuthResponse
	if err := v.websocketConnection.ReadJSON(&authResponse); err != nil {
		return err
	}
	if authResponse.Kind == "Error" {
		return errors.New(authResponse.Text)
	}
	if !authResponse.Success {
		return errors.New("failed to authenticate")
	}

	v.sessionId = authResponse.SessionId

	return nil
}

func (v *vaas) ForSha256(sha256 string) (msg.VaasVerdict, error) {
	if v.sessionId == "" {
		return msg.VaasVerdict{}, errors.New("invalid operation")
	}
	subscription := v.broadcastChannel.Subscribe()
	defer v.broadcastChannel.RemoveSubscription(subscription)
	request := msg.NewVerdictRequest(v.sessionId, v.options, sha256)
	v.requestChannel <- request

	verdictResponse, err := v.waitForResponse(subscription, request.GetGuid())
	if err != nil {
		return msg.VaasVerdict{
			Verdict: msg.Verdict(msg.Error),
			Sha256:  sha256,
		}, err
	}

	return msg.VaasVerdict{
		Verdict: verdictResponse.Verdict,
		Sha256:  verdictResponse.Sha256,
	}, nil
}

func (v *vaas) ForSha256List(sha256List []string) ([]msg.VaasVerdict, error) {
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

func (v *vaas) ForFile(filePath string) (msg.VaasVerdict, error) {
	if v.sessionId == "" {
		return msg.VaasVerdict{}, errors.New("invalid operation")
	}

	file, err := os.Open(filePath)
	defer func() {
		_ = file.Close()
	}()

	if err != nil {
		return msg.VaasVerdict{
			Verdict: msg.Verdict(msg.Error),
		}, err
	}

	sha256, err := hash.CalculateSha256(file)
	if err != nil {
		return msg.VaasVerdict{
			Verdict: msg.Verdict(msg.Error),
		}, err
	}

	_, err = file.Seek(0, 0)
	if err != nil {
		return msg.VaasVerdict{
			Verdict: msg.Verdict(msg.Error),
		}, err
	}

	return v.forFileWithSha(file, sha256)
}

func (v *vaas) ForFileInMemory(data io.Reader) (msg.VaasVerdict, error) {
	if v.sessionId == "" {
		return msg.VaasVerdict{}, errors.New("invalid operation")
	}

	buf := new(bytes.Buffer)
	_, err := io.Copy(buf, data)
	if err != nil {
		return msg.VaasVerdict{
			Verdict: msg.Verdict(msg.Error),
		}, err
	}

	sha256, err := hash.CalculateSha256(bytes.NewReader(buf.Bytes()))
	if err != nil {
		return msg.VaasVerdict{
			Verdict: msg.Verdict(msg.Error),
		}, err
	}

	return v.forFileWithSha(bytes.NewReader(buf.Bytes()), sha256)
}

func (v *vaas) forFileWithSha(data io.Reader, sha256 string) (msg.VaasVerdict, error) {
	if v.sessionId == "" {
		return msg.VaasVerdict{}, errors.New("invalid operation")
	}

	subscription := v.broadcastChannel.Subscribe()
	defer v.broadcastChannel.RemoveSubscription(subscription)

	request := msg.NewVerdictRequest(v.sessionId, v.options, sha256)
	v.requestChannel <- request

	response, err := v.waitForResponse(subscription, request.GetGuid())
	if err != nil {
		return msg.VaasVerdict{
			Verdict: msg.Verdict(msg.Error),
			Sha256:  sha256,
		}, err
	}

	if response.Verdict == msg.Verdict(msg.Unknown) {
		if err := v.uploadFile(data, response.Url, response.UploadToken); err != nil {
			return msg.VaasVerdict{
				Verdict: msg.Verdict(msg.Unknown),
				Sha256:  sha256,
			}, err
		} else {
			uploadResponse, err := v.waitForResponse(subscription, request.GetGuid())
			if err != nil {
				return msg.VaasVerdict{
					Verdict: msg.Verdict(msg.Error),
					Sha256:  sha256,
				}, err
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

func (v *vaas) ForFileList(fileList []string) ([]msg.VaasVerdict, error) {
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

func (v *vaas) ForUrl(url string) (msg.VaasVerdict, error) {
	if v.sessionId == "" {
		return msg.VaasVerdict{}, errors.New("invalid operation")
	}
	subscription := v.broadcastChannel.Subscribe()
	defer v.broadcastChannel.RemoveSubscription(subscription)
	request := msg.NewVerdictRequestForUrl(v.sessionId, v.options, url)
	v.requestChannel <- request

	verdictResponse, responseErr := v.waitForResponse(subscription, request.GetGuid())
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

func (v *vaas) uploadFile(file io.Reader, url string, token string) error {
	httpClient := &http.Client{}
	req, err := http.NewRequest(http.MethodPut, url, file)
	if err != nil {
		return err
	}

	req.Header.Add("Authorization", token)

	httpResponse, err := httpClient.Do(req)
	if err != nil {
		return err
	}

	if httpResponse.StatusCode != 200 {
		return errors.New("StatusCode:" + fmt.Sprintf("%x", httpResponse.StatusCode))
	}

	return nil
}

func (v *vaas) waitForResponse(subscription <-chan msg.VerdictResponse, guid string) (msg.VerdictResponse, error) {
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

func (v *vaas) sendRequests(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case request := <-v.requestChannel:
			if err := v.websocketConnection.WriteJSON(request); err != nil {
				log.Fatal(err)
			}
		}
	}
}

func (v *vaas) readResponses(ctx context.Context) {
	responseChan := make(chan msg.VerdictResponse, 1)

	go func() {
		for {
			var verdictResponse msg.VerdictResponse
			select {
			case <-ctx.Done():
				v.websocketConnection.Close()
				return
			default:

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
		}
	}()

	for {
		select {
		case <-ctx.Done():
			v.websocketConnection.Close()
			return
		case response := <-responseChan:
			v.responseChannel <- response
		}
	}
}
