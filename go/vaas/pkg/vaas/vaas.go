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
	var waitgroup sync.WaitGroup
	var connectErr error = nil

	waitgroup.Add(1)
	go func() {
		defer waitgroup.Done()

		connection, _, websocketErr := websocket.DefaultDialer.Dial("wss://gateway-vaas.gdatasecurity.de", nil)
		if websocketErr != nil {
			connectErr = websocketErr
		}
		v.websocketConnection = connection

		if err := v.Authenticate(token); err != nil {
			connectErr = errors.New("failed to authenticate: " + err.Error())
		}
	}()
	waitgroup.Wait()

	return connectErr
}

func (v *Vaas) Authenticate(token string) error {
	var waitGroup sync.WaitGroup
	var authError error = nil

	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		v.websocketConnection.WriteJSON(msg.AuthRequest{
			Kind:  "AuthRequest",
			Token: token,
		})

		var authResponse msg.AuthResponse
		v.websocketConnection.ReadJSON(&authResponse)
		if authResponse.Kind == "Error" {
			authError = errors.New(authResponse.Text)
		}
		if !authResponse.Success {
			authError = errors.New("failed to authenticate")
		}

		v.sessionId = authResponse.SessionId
	}()
	waitGroup.Wait()

	return authError
}

func (v *Vaas) ForSha256(sha256 string) (msg.VaasVerdict, error) {
	if v.sessionId == "" {
		return msg.VaasVerdict{}, errors.New("invalid operation")
	}

	var waitGroup sync.WaitGroup
	var verdict msg.VaasVerdict
	var err error = nil

	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		request := msg.NewVerdictRequest(v.sessionId, v.options, sha256)
		if requestErr := v.forRequest(request); requestErr != nil {
			err = requestErr
			return
		}

		response, responseErr := v.forResponse()
		if responseErr != nil {
			err = responseErr
			return
		}

		verdict = msg.VaasVerdict{
			Verdict: response.Verdict,
			Sha256:  response.Sha256,
		}
	}()
	waitGroup.Wait()

	return verdict, err
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

	var waitGroup sync.WaitGroup
	var verdict msg.VaasVerdict
	var err error

	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		data, fileErr := os.Open(file)
		if fileErr != nil {
			err = fileErr
			return
		}

		sha256, parseErr := utilities.ToSha256String(data)
		if parseErr != nil {
			err = parseErr
			return
		}

		request := msg.NewVerdictRequest(v.sessionId, v.options, sha256)
		if requestErr := v.forRequest(request); err != nil {
			err = requestErr
			return
		}

		response, responseErr := v.forResponse()
		if err != nil {
			err = responseErr
			return
		}

		verdict = msg.VaasVerdict{
			Verdict: response.Verdict,
			Sha256:  request.Sha256,
		}

		if response.Verdict == msg.Verdict(msg.Unknown) {
			if uploadErr := v.uploadFile(data, response.Url, response.UploadToken); uploadErr != nil {
				err = uploadErr
				return
			} else {
				uploadResponse, responseErr := v.forResponse()
				if responseErr != nil {
					err = responseErr
					return
				} else {
					verdict = msg.VaasVerdict{
						Verdict: uploadResponse.Verdict,
						Sha256:  uploadResponse.Sha256,
					}
				}
			}
		}
	}()

	waitGroup.Wait()

	return verdict, nil
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

	var waitGroup sync.WaitGroup
	var verdict msg.VaasVerdict
	var err error = nil

	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		request := msg.NewVerdictRequest(v.sessionId, v.options, url)
		if requestErr := v.forRequest(request); requestErr != nil {
			err = requestErr
			return
		}

		response, responseErr := v.forResponse()
		if responseErr != nil {
			err = responseErr
			return
		}
		verdict = msg.VaasVerdict{
			Verdict: response.Verdict,
			Sha256:  request.Sha256,
		}
	}()
	waitGroup.Wait()

	return verdict, err
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
