package vaas

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/authenticator"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/hash"
	msg "github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/messages"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/options"
	"github.com/gorilla/websocket"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
)

type Vaas interface {
	Connect(ctx context.Context, auth authenticator.ClientCredentialsGrantAuthenticator) (termChan <-chan error, err error)
	ForUrl(uri string) (msg.VaasVerdict, error)
	ForSha256(sha256 string) (msg.VaasVerdict, error)
	ForFile(path string) (msg.VaasVerdict, error)
	ForFileInMemory(file io.Reader) (msg.VaasVerdict, error)
	ForSha256List(sha256List []string) ([]msg.VaasVerdict, error)
	ForFileList(fileList []string) ([]msg.VaasVerdict, error)
}

type vaas struct {
	logger              *log.Logger
	sessionId           string
	websocketConnection *websocket.Conn
	waitAuthenticated   sync.WaitGroup

	openRequests      map[string]chan msg.VerdictResponse
	openRequestsMutex sync.Mutex

	requestChannel  chan msg.VerdictRequest
	responseChannel chan msg.VerdictResponse
	vaasUrl         string
	options         options.VaasOptions
}

func New(options options.VaasOptions, vaasUrl string) Vaas {
	client := &vaas{
		logger:          log.Default(),
		options:         options,
		vaasUrl:         vaasUrl,
		requestChannel:  make(chan msg.VerdictRequest, 1),
		responseChannel: make(chan msg.VerdictResponse),
		openRequests:    make(map[string]chan msg.VerdictResponse, 0),
	}
	return client
}

func (v *vaas) Connect(ctx context.Context, auth authenticator.ClientCredentialsGrantAuthenticator) (termChan <-chan error, err error) {
	if err = v.authenticate(ctx, auth); err != nil {
		return nil, err
	}

	go v.sendRequests(ctx)
	termChan = v.listenWebSocket()

	return termChan, nil
}

func (v *vaas) ForSha256(sha256 string) (msg.VaasVerdict, error) {
	if v.sessionId == "" {
		return msg.VaasVerdict{}, errors.New("invalid operation")
	}

	request := msg.NewVerdictRequest(v.sessionId, v.options, sha256)

	responseChannel := v.openRequest(request)
	defer v.closeRequest(request)

	response := <-responseChannel

	return msg.VaasVerdict{
		Verdict: response.Verdict,
		Sha256:  response.Sha256,
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
				verdicts = append(verdicts, msg.VaasVerdict{Sha256: sha256, Verdict: msg.Error, ErrMsg: err.Error()})
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
			Verdict: msg.Error,
			ErrMsg:  err.Error(),
		}, err
	}

	sha256, err := hash.CalculateSha256(file)
	if err != nil {
		return msg.VaasVerdict{
			Verdict: msg.Error,
			ErrMsg:  err.Error(),
		}, err
	}

	_, err = file.Seek(0, 0)
	if err != nil {
		return msg.VaasVerdict{
			Verdict: msg.Error,
			ErrMsg:  err.Error(),
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
			Verdict: msg.Error,
			ErrMsg:  err.Error(),
		}, err
	}

	sha256, err := hash.CalculateSha256(bytes.NewReader(buf.Bytes()))
	if err != nil {
		return msg.VaasVerdict{
			Verdict: msg.Error,
			ErrMsg:  err.Error(),
		}, err
	}

	return v.forFileWithSha(bytes.NewReader(buf.Bytes()), sha256)
}

func (v *vaas) ForFileList(fileList []string) ([]msg.VaasVerdict, error) {
	if v.sessionId == "" {
		return nil, errors.New("invalid operation")
	}

	var waitGroup sync.WaitGroup
	var verdicts []msg.VaasVerdict

	for _, file := range fileList {
		waitGroup.Add(1)

		go func(file string) {
			defer waitGroup.Done()
			verdict, err := v.ForFile(file)
			if err != nil {
				verdicts = append(verdicts, msg.VaasVerdict{Sha256: verdict.Sha256, Verdict: msg.Error, ErrMsg: err.Error()})
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

	request := msg.NewVerdictRequestForUrl(v.sessionId, v.options, url)

	responseChan := v.openRequest(request)
	defer v.closeRequest(request)

	verdictResponse := <-responseChan

	return msg.VaasVerdict{
		Verdict: verdictResponse.Verdict,
		Sha256:  verdictResponse.Sha256,
	}, nil
}

func (v *vaas) authenticate(ctx context.Context, auth authenticator.ClientCredentialsGrantAuthenticator) error {
	v.waitAuthenticated.Add(1)
	defer v.waitAuthenticated.Done()

	connection, _, err := websocket.DefaultDialer.DialContext(ctx, v.vaasUrl, nil)
	if err != nil {
		return err
	}
	connection.SetPingHandler(nil)
	v.websocketConnection = connection

	var token string
	if token, err = auth.GetToken(); err != nil {
		return err
	}

	if err = v.websocketConnection.WriteJSON(msg.AuthRequest{
		Kind:  "AuthRequest",
		Token: token,
	}); err != nil {
		return err
	}

	var authResponse msg.AuthResponse
	if err = v.websocketConnection.ReadJSON(&authResponse); err != nil {
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

func (v *vaas) forFileWithSha(data io.Reader, sha256 string) (msg.VaasVerdict, error) {
	if v.sessionId == "" {
		return msg.VaasVerdict{}, errors.New("invalid operation")
	}

	request := msg.NewVerdictRequest(v.sessionId, v.options, sha256)
	responseChan := v.openRequest(request)
	defer v.closeRequest(request)

	response := <-responseChan

	if response.Verdict == msg.Unknown {
		if err := v.uploadFile(data, response.Url, response.UploadToken); err != nil {
			return msg.VaasVerdict{
				Verdict: msg.Error,
				Sha256:  sha256,
				ErrMsg:  err.Error(),
			}, err
		}
		response = <-responseChan
	}

	return msg.VaasVerdict{
		Verdict: response.Verdict,
		Sha256:  response.Sha256,
	}, nil
}

func (v *vaas) openRequest(request msg.VerdictRequest) <-chan msg.VerdictResponse {
	if v.options.EnableLogs {
		v.logger.Printf("Opening request for %s", request.GetGuid())
	}

	v.waitAuthenticated.Wait()

	v.openRequestsMutex.Lock()
	resultChan := make(chan msg.VerdictResponse, 1)
	v.openRequests[request.GetGuid()] = resultChan
	v.openRequestsMutex.Unlock()
	v.requestChannel <- request
	return resultChan
}

func (v *vaas) closeRequest(request msg.VerdictRequest) {
	if v.options.EnableLogs {
		v.logger.Printf("Closing request for %s", request.GetGuid())
	}

	v.openRequestsMutex.Lock()
	close(v.openRequests[request.GetGuid()])
	delete(v.openRequests, request.GetGuid())
	v.openRequestsMutex.Unlock()
}

func (v *vaas) uploadFile(file io.Reader, url string, token string) error {
	req, err := http.NewRequest(http.MethodPut, url, file)
	if err != nil {
		return err
	}

	// VAAS requires a set Content-Length.
	// Here can add support for various io.Reader, which are not supported by the http package.
	if req.ContentLength == 0 {
		switch t := file.(type) {
		case *os.File:
			var info os.FileInfo
			if info, err = t.Stat(); err != nil {
				return err
			}
			req.ContentLength = info.Size()
		default:
			return fmt.Errorf("unsupported reader (%T), can not determine content length", file)
		}
	}

	req.Header.Add("Authorization", token)

	httpResponse, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer httpResponse.Body.Close()

	if httpResponse.StatusCode != 200 {
		errMsg, _ := io.ReadAll(httpResponse.Body)
		return fmt.Errorf("StatusCode: %d, Msg: %s", httpResponse.StatusCode, errMsg)
	}

	return nil
}

func (v *vaas) sendRequests(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case request := <-v.requestChannel:
			if err := v.websocketConnection.WriteJSON(request); err != nil {
				if v.options.EnableLogs {
					v.logger.Printf("Failed to send request %v", err)
				}
				return
			}
		}
	}
}

func (v *vaas) listenWebSocket() chan error {
	termChan := make(chan error, 1)
	defer close(termChan)

	go func() {
		var verdictResponse msg.VerdictResponse
		for {
			err := v.websocketConnection.ReadJSON(&verdictResponse)
			if err == nil {
				v.openRequests[verdictResponse.Guid] <- verdictResponse
				continue
			}

			var closeErr *websocket.CloseError
			if errors.As(err, &closeErr) {
				switch closeErr.Code {
				case websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseNoStatusReceived:
					if v.options.EnableLogs {
						v.logger.Printf("Websocket shutdown - %d: %s", closeErr.Code, closeErr.Text)
					}
					return
				default:
					termChan <- fmt.Errorf("unexpected shutdown of websocket - %w", closeErr)
					return
				}
			}
			if err == io.ErrUnexpectedEOF {
				if v.options.EnableLogs {
					v.logger.Printf("Temporarily failed to read from websocket: %v", err)
				}
				continue
			}
			if v.options.EnableLogs {
				v.logger.Printf("Permanently failed to read from websocket: %v", err)
			}
			termChan <- fmt.Errorf("unexpected error of websocket connection - %w", err)
			return
		}
	}()

	return termChan
}
