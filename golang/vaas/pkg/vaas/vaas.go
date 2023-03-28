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
	"net"
	"net/http"
	"os"
	"sync"
)

// Vaas provides various ForXXX-functions to send analysis requests to a VAAS server.
// All kinds of request can be canceled by the context.
// The Connect()-function has to be called before any other requests are made.
type Vaas interface {
	// Connect opens a websocket connection to the VAAS Server, which is kept open until the context.Context expires.
	// The termChan indicates when a connection was closed. In the case of an unexpected close an error is written to the channel.
	Connect(ctx context.Context, auth authenticator.ClientCredentialsGrantAuthenticator) (termChan <-chan error, err error)
	ForUrl(ctx context.Context, uri string) (msg.VaasVerdict, error)
	ForSha256(ctx context.Context, sha256 string) (msg.VaasVerdict, error)
	ForFile(ctx context.Context, path string) (msg.VaasVerdict, error)
	ForFileInMemory(ctx context.Context, file io.Reader) (msg.VaasVerdict, error)
	ForSha256List(ctx context.Context, sha256List []string) ([]msg.VaasVerdict, error)
	ForFileList(ctx context.Context, fileList []string) ([]msg.VaasVerdict, error)
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
	termChan = v.listenWebSocket(ctx)

	return termChan, nil
}

func (v *vaas) ForSha256(ctx context.Context, sha256 string) (msg.VaasVerdict, error) {
	if v.sessionId == "" {
		return msg.VaasVerdict{}, errors.New("invalid operation")
	}

	request := msg.NewVerdictRequest(v.sessionId, v.options, sha256)

	responseChannel := v.openRequest(request)
	defer v.closeRequest(request)

	var response msg.VerdictResponse
	select {
	case response = <-responseChannel:
	case <-ctx.Done():
		return msg.VaasVerdict{}, ctx.Err()
	}

	return msg.VaasVerdict{
		Verdict: response.Verdict,
		Sha256:  response.Sha256,
	}, nil
}

func (v *vaas) ForSha256List(ctx context.Context, sha256List []string) ([]msg.VaasVerdict, error) {
	if v.sessionId == "" {
		return []msg.VaasVerdict{}, errors.New("invalid operation")
	}

	var writerGroup sync.WaitGroup
	var verdicts []msg.VaasVerdict

	for _, sha256 := range sha256List {
		writerGroup.Add(1)
		go func(sha256 string) {
			defer writerGroup.Done()
			verdict, err := v.ForSha256(ctx, sha256)
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

func (v *vaas) ForFile(ctx context.Context, filePath string) (msg.VaasVerdict, error) {
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

	return v.forFileWithSha(ctx, file, sha256)
}

func (v *vaas) ForFileInMemory(ctx context.Context, data io.Reader) (msg.VaasVerdict, error) {
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

	return v.forFileWithSha(ctx, bytes.NewReader(buf.Bytes()), sha256)
}

func (v *vaas) ForFileList(ctx context.Context, fileList []string) ([]msg.VaasVerdict, error) {
	if v.sessionId == "" {
		return nil, errors.New("invalid operation")
	}

	var waitGroup sync.WaitGroup
	var verdicts []msg.VaasVerdict

	for _, file := range fileList {
		waitGroup.Add(1)

		go func(file string) {
			defer waitGroup.Done()
			verdict, err := v.ForFile(ctx, file)
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

func (v *vaas) ForUrl(ctx context.Context, url string) (msg.VaasVerdict, error) {
	if v.sessionId == "" {
		return msg.VaasVerdict{}, errors.New("invalid operation")
	}

	request := msg.NewVerdictRequestForUrl(v.sessionId, v.options, url)

	responseChan := v.openRequest(request)
	defer v.closeRequest(request)

	var response msg.VerdictResponse
	select {
	case response = <-responseChan:
	case <-ctx.Done():
		return msg.VaasVerdict{}, ctx.Err()
	}

	return msg.VaasVerdict{
		Verdict: response.Verdict,
		Sha256:  response.Sha256,
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

func (v *vaas) forFileWithSha(ctx context.Context, data io.Reader, sha256 string) (msg.VaasVerdict, error) {
	if v.sessionId == "" {
		return msg.VaasVerdict{}, errors.New("invalid operation")
	}

	request := msg.NewVerdictRequest(v.sessionId, v.options, sha256)
	responseChan := v.openRequest(request)
	defer v.closeRequest(request)

	var response msg.VerdictResponse
	select {
	case response = <-responseChan:
	case <-ctx.Done():
		return msg.VaasVerdict{}, ctx.Err()
	}

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

func (v *vaas) listenWebSocket(ctx context.Context) chan error {
	termChan := make(chan error, 2)
	listenCtx, listenCancel := context.WithCancel(ctx)

	go func() {
		<-listenCtx.Done()
		termChan <- v.websocketConnection.Close()
		close(termChan)
	}()

	go func() {
		defer listenCancel()

		var verdictResponse msg.VerdictResponse
		for {
			err := v.websocketConnection.ReadJSON(&verdictResponse)
			if err == nil {
				v.openRequests[verdictResponse.Guid] <- verdictResponse
				continue
			}

			var closeErr *websocket.CloseError
			// If websocket was shutdown by the server
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
			// This error occurs when the context is canceled and we call close() on the websocket connection.
			if errors.Is(err, net.ErrClosed) {
				if v.options.EnableLogs {
					v.logger.Printf("Websocket connection was closed")
				}
				return
			}
			// This error occurs if whe JSON response could not be parsed by the websocket.
			if err == io.ErrUnexpectedEOF {
				if v.options.EnableLogs {
					v.logger.Printf("Temporarily failed to read from websocket: %v", err)
				}
				continue
			}
			// We don't know what happened here, help...
			if v.options.EnableLogs {
				v.logger.Printf("Permanently failed to read from websocket: %v", err)
			}
			termChan <- fmt.Errorf("unexpected error of websocket connection - %w", err)
			return
		}
	}()

	return termChan
}
