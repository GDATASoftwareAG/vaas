package vaas

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"

	msg "vaas/pkg/messages"
	"vaas/pkg/options"
	"vaas/pkg/utilities"

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

func (v *Vaas) Connect(token string) error {
	connection, _, websocketErr := websocket.DefaultDialer.Dial("wss://gateway-vaas.gdatasecurity.de", nil)
	if websocketErr != nil {
		return websocketErr
	}
	v.websocketConnection = connection

	if err := v.Authenticate(token); err != nil {
		return errors.New("failed to authenticate: " + err.Error())
	}
	
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

	request := msg.VerdictRequest{}.New(v.sessionId, v.options, sha256)
	if requestErr := v.forRequest(request); requestErr != nil {
		return msg.VaasVerdict{
			Verdict: msg.Verdict(msg.Error),
			Sha256: sha256,
		}, requestErr
	}

	response, responseErr := v.forResponse()
	if responseErr != nil {
		return msg.VaasVerdict{
			Verdict: msg.Verdict(msg.Error),
			Sha256: sha256,
		}, responseErr

	}

	return msg.VaasVerdict{
		Verdict: response.Verdict,
		Sha256:  response.Sha256,
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

	sha256, parseErr := utilities.ToSha256String(data)
	if parseErr != nil {
		return msg.VaasVerdict{
			Verdict: msg.Verdict(msg.Error),
		}, parseErr
	}

	request := msg.VerdictRequest{}.New(v.sessionId, v.options, sha256)
	if requestErr := v.forRequest(request); requestErr != nil {
		return msg.VaasVerdict{
			Verdict: msg.Verdict(msg.Error),
			Sha256: sha256,
		}, requestErr
	}

	response, responseErr := v.forResponse()
	if responseErr != nil {
		return msg.VaasVerdict{
			Verdict: msg.Verdict(msg.Error),
			Sha256: sha256,
		}, responseErr
	}

	if response.Verdict == msg.Verdict(msg.Unknown) {
		if uploadErr := v.uploadFile(data, response.Url, response.UploadToken); uploadErr != nil {
			return msg.VaasVerdict{
				Verdict: msg.Verdict(msg.Unknown),
				Sha256: sha256,
			}, uploadErr
		} else {
			uploadResponse, responseErr := v.forResponse()
			if responseErr != nil {
				return msg.VaasVerdict{
					Verdict: msg.Verdict(msg.Error),
					Sha256: sha256,
				}, responseErr
			} else {
				response = uploadResponse
			}
		}
	}
	
	return msg.VaasVerdict{
		Verdict: response.Verdict,
		Sha256: response.Sha256,
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

		go func() {
			defer waitGroup.Done()
			verdict, err := v.ForFile(file)
			if err != nil {
				verdicts = append(verdicts, msg.VaasVerdict{Sha256: verdict.Sha256, Verdict: msg.Verdict(msg.Error)})
			} else {
				verdicts = append(verdicts, verdict)
			}
		}()

		waitGroup.Wait()
	}
	return verdicts, nil
}

func (v *Vaas) ForUrl(url string) (msg.VaasVerdict, error) {
	if v.sessionId == "" {
		return msg.VaasVerdict{}, errors.New("invalid operation")
	}

	request := msg.VerdictRequestForUrl{}.New(v.sessionId, v.options, url)
	if requestErr := v.forRequest(request); requestErr != nil {
		return msg.VaasVerdict{
			Verdict: msg.Verdict(msg.Error),
		}, requestErr
	}

	response, responseErr := v.forResponse()
	if responseErr != nil {
		return msg.VaasVerdict{
			Verdict: msg.Verdict(msg.Error),
		}, responseErr
	}

	return msg.VaasVerdict{
		Verdict: response.Verdict,
	}, nil
}

func (v *Vaas) forRequest(verdictRequest msg.IVerdictRequest) error {
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
