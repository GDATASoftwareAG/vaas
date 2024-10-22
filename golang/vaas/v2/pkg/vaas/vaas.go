// Package vaas provides a client for interacting with G DATA CyberDefense's VaaS Service
// for sending analysis requests to the Vaas server for various types of data, such as URLs, SHA256 hashes, and files.
package vaas

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"

	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/GDATASoftwareAG/vaas/golang/vaas/v2/internal/hash"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/v2/pkg/authenticator"
	msg "github.com/GDATASoftwareAG/vaas/golang/vaas/v2/pkg/messages"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/v2/pkg/options"
	"github.com/Noooste/websocket"
)

// Vaas provides various ForXXX-functions to send analysis requests to a VaaS server.
// All kinds of requests can be canceled by the context.
// The Connect() function has to be called before any other requests are made.
// Please refer to the individual function comments for more details on their usage and behavior.
type Vaas interface {
	io.Closer
	Connect(ctx context.Context, auth authenticator.Authenticator) (errorChan <-chan error, err error)
	ForUrl(ctx context.Context, uri string) (msg.VaasVerdict, error)
	ForStream(ctx context.Context, stream io.Reader, contentLength int64) (msg.VaasVerdict, error)
	ForSha256(ctx context.Context, sha256 string) (msg.VaasVerdict, error)
	ForFile(ctx context.Context, path string) (msg.VaasVerdict, error)
	ForFileInMemory(ctx context.Context, file io.Reader) (msg.VaasVerdict, error)
	ForSha256List(ctx context.Context, sha256List []string) ([]msg.VaasVerdict, error)
	ForFileList(ctx context.Context, fileList []string) ([]msg.VaasVerdict, error)
}

type websocketConnection interface {
	io.Closer
	ReadMessage() (messageType int, p []byte, err error)
	// TODO: Replace with ReadMessage
	ReadJSON(data any) error
	WriteJSON(data any) error
	SetWriteDeadline(add time.Time) error
	WriteMessage(messageType int, data []byte) error
	SetReadDeadline(t time.Time) error
	SetPongHandler(h func(appData string) error)
}

// Confer example for constants, pong handler, and ping ticker
// https://github.com/Noooste/websocket/blob/master/examples/chat/client.go
const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 30 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10
)

var (
	ErrUnsupportedReader = errors.New("unsupported reader")
)

// vaas provides the implementation of the Vaas interface.
type vaas struct {
	options       options.VaasOptions
	vaasURL       string
	authenticator authenticator.Authenticator

	// TODO: Replace with zap
	logger            *log.Logger
	shutdownOnce      sync.Once
	requestChannel    chan msg.VerdictRequest
	openRequestsMutex sync.Mutex
	openRequests      map[string]chan msg.VerdictResponse

	connectionLoopTermChan chan struct{}
}

// New creates a new instance of the Vaas struct, which represents a client for interacting with a Vaas service.
// The vaasURL parameter specifies the endpoint for the VaaS service.
func New(options options.VaasOptions, vaasURL string, authenticator authenticator.Authenticator) Vaas {
	client := &vaas{
		logger:                 log.Default(),
		options:                options,
		vaasURL:                vaasURL,
		requestChannel:         make(chan msg.VerdictRequest, 1),
		openRequests:           make(map[string]chan msg.VerdictResponse, 0),
		authenticator:          authenticator,
		connectionLoopTermChan: make(chan struct{}, 1),
	}
	// TODO: what's the right pattern for functions that start goroutines?
	go client.connectLoop()
	return client
}

// NewWithDefaultEndpoint creates a new instance of the Vaas struct with a default endpoint.
// It represents a client for interacting with a Vaas service.
func NewWithDefaultEndpoint(options options.VaasOptions, authenticator authenticator.Authenticator) Vaas {
	return New(options, "wss://gateway.production.vaas.gdatasecurity.de", authenticator)
}

// Close terminates the websocket connection.
func (v *vaas) Close() (err error) {
	v.shutdownOnce.Do(func() {
		close(v.requestChannel)
	})

	// TODO: wait for connectionLoop

	//if err = v.websocketConnection.Close(); err != nil && v.options.EnableLogs {
	//	v.logger.Printf("Failed to close web socket: %v", err)
	//}

	return
}

// Connect opens a websocket connection to the VAAS Server. Use Close() to terminate the connection.
// The errorChan indicates when a connection was closed. In the case of an unexpected close, an error is written to the channel.
//
// Example usage:
//
//	vaasClient := vaas.New(options, "wss://example.authentication.endpoint")
//	ctx := context.Background()
//	auth := authenticator.NewClientCredentialsGrantAuthenticator("client_id", "client_secret")
//	errorChan, err := vaasClient.Connect(ctx, auth)
//	defer vaasClient.Close()
//	if err != nil {
//	    log.Fatalf("Failed to connect to VaaS: %v", err)
//	}
func (v *vaas) Connect(ctx context.Context, auth authenticator.Authenticator) (errorChan <-chan error, err error) {
	fakeErrChan := make(chan error)
	go func() {
		<-v.connectionLoopTermChan
		fakeErrChan <- nil
	}()
	return fakeErrChan, nil
}

// ForSha256 sends an analysis request for a file identified by its SHA256 hash to the Vaas server and returns the verdict.
// The analysis can be canceled using the provided context.
//
// Example usage:
//
//	vaasClient := vaas.New(options, "wss://example.authentication.endpoint")
//	ctx := context.Background()
//	sha256 := "..."
//	verdict, err := vaasClient.ForSha256(ctx, sha256)
//	if err != nil {
//	    log.Fatalf("Failed to get verdict: %v", err)
//	}
//	fmt.Printf("Verdict: %s\n", verdict.Verdict)
//	fmt.Printf("SHA256: %s\n", verdict.Sha256)
func (v *vaas) ForSha256(ctx context.Context, sha256 string) (msg.VaasVerdict, error) {
	request := msg.NewVerdictRequest("", v.options, sha256)

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

// ForSha256List sends analysis requests for a list of SHA256 hashes to the Vaas server and returns the verdicts.
// The analysis can be canceled using the provided context.
//
// Example usage:
//
//	vaasClient := vaas.New(options, "wss://example.authentication.endpoint")
//	ctx := context.Background()
//	sha256List := []string{"sha256_hash_1", "sha256_hash_2"}
//	verdicts, err := vaasClient.ForSha256List(ctx, sha256List)
//	if err != nil {
//	    log.Fatalf("Failed to get verdicts: %v", err)
//	}
//	for _, verdict := range verdicts {
//	    fmt.Printf("SHA256: %s\n", verdict.Sha256)
//	    fmt.Printf("Verdict: %s\n", verdict.Verdict)
//	}
func (v *vaas) ForSha256List(ctx context.Context, sha256List []string) ([]msg.VaasVerdict, error) {
	var waitGroup sync.WaitGroup
	verdicts := make([]msg.VaasVerdict, len(sha256List))

	for i, sha256 := range sha256List {
		waitGroup.Add(1)
		go func(i int, sha256 string) {
			defer waitGroup.Done()
			verdict, err := v.ForSha256(ctx, sha256)
			if err != nil {
				verdict = msg.VaasVerdict{Sha256: sha256, Verdict: msg.Error, ErrMsg: err.Error(),
					Detection: verdict.Detection, FileType: verdict.FileType, MimeType: verdict.MimeType}
			}
			verdicts[i] = verdict
		}(i, sha256)
	}
	waitGroup.Wait()

	return verdicts, nil
}

// ForFile sends an analysis request for a file at the given filePath to the Vaas server and returns the verdict.
// The analysis can be canceled using the provided context.
//
// Example usage:
//
//	vaasClient := vaas.New(options, "wss://example.authentication.endpoint")
//	ctx := context.Background()
//	filePath := "path/to/file.txt"
//	verdict, err := vaasClient.ForFile(ctx, filePath)
//	if err != nil {
//	    log.Fatalf("Failed to get verdict: %v", err)
//	}
//	fmt.Printf("Verdict: %s\n", verdict.Verdict)
//	fmt.Printf("SHA256: %s\n", verdict.Sha256)
func (v *vaas) ForFile(ctx context.Context, filePath string) (msg.VaasVerdict, error) {
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

	if _, err = file.Seek(0, 0); err != nil {
		return msg.VaasVerdict{
			Verdict: msg.Error,
			ErrMsg:  err.Error(),
		}, err
	}

	return v.forFileWithSha(ctx, file, sha256)
}

// ForFileInMemory sends an analysis request for file data provided as an io.Reader to the Vaas server and returns the verdict.
// The analysis can be canceled using the provided context.
//
// Example usage:
//
//	vaasClient := vaas.New(options, "wss://example.authentication.endpoint")
//	ctx := context.Background()
//	fileData := bytes.NewReader([]byte("file contents"))
//	verdict, err := vaasClient.ForFileInMemory(ctx, fileData)
//	if err != nil {
//	    log.Fatalf("Failed to get verdict: %v", err)
//	}
//	fmt.Printf("Verdict: %s\n", verdict.Verdict)
//	fmt.Printf("SHA256: %s\n", verdict.Sha256)
func (v *vaas) ForFileInMemory(ctx context.Context, data io.Reader) (msg.VaasVerdict, error) {
	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, data); err != nil {
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

// ForFileList sends analysis requests for a list of file paths to the Vaas server and returns the verdicts.
// The analysis can be canceled using the provided context.
//
// Example usage:
//
//	vaasClient := vaas.New(options,  "wss://example.authentication.endpoint")
//	ctx := context.Background()
//	fileList := []string{"path/to/file1.txt", "path/to/file2.txt"}
//	verdicts, err := vaasClient.ForFileList(ctx, fileList)
//	if err != nil {
//	    log.Fatalf("Failed to get verdicts: %v", err)
//	}
//	for _, verdict := range verdicts {
//	    fmt.Printf("File: %s\n", verdict.Sha256)
//	    fmt.Printf("Verdict: %s\n", verdict.Verdict)
//	}
func (v *vaas) ForFileList(ctx context.Context, fileList []string) ([]msg.VaasVerdict, error) {
	var waitGroup sync.WaitGroup
	verdicts := make([]msg.VaasVerdict, len(fileList))

	for i, file := range fileList {
		waitGroup.Add(1)

		go func(i int, file string) {
			defer waitGroup.Done()
			verdict, err := v.ForFile(ctx, file)
			if err != nil {
				verdict = msg.VaasVerdict{Verdict: msg.Error, ErrMsg: err.Error()}
			}
			verdicts[i] = verdict
		}(i, file)
	}
	waitGroup.Wait()
	return verdicts, nil
}

// ForUrl sends an analysis request for a file URL to the Vaas server and returns the verdict.
// The analysis can be canceled using the provided context.
//
// Example usage:
//
//	vaasClient := vaas.New(options, "wss://example.authentication.endpoint")
//	ctx := context.Background()
//	verdict, err := vaasClient.ForUrl(ctx, "https://example.com/examplefile")
//	if err != nil {
//	    log.Fatalf("Failed to get verdict: %v", err)
//	}
//	fmt.Printf("Verdict: %s\n", verdict.Verdict)
//	fmt.Printf("SHA256: %s\n", verdict.Sha256)
func (v *vaas) ForUrl(ctx context.Context, url string) (msg.VaasVerdict, error) {
	request := msg.NewVerdictRequestForURL("", v.options, url)

	responseChan := v.openRequest(request)
	defer v.closeRequest(request)

	var response msg.VerdictResponse
	select {
	case response = <-responseChan:
	case <-ctx.Done():
		return msg.VaasVerdict{}, ctx.Err()
	}

	return msg.VaasVerdict{
		Verdict:   response.Verdict,
		Sha256:    response.Sha256,
		Detection: response.Detection,
		MimeType:  response.MimeType,
		FileType:  response.FileType,
	}, nil
}

// ForStream sends an analysis request for a file stream to the Vaas server and returns the verdict.
// The analysis can be canceled using the provided context.
// ContentLength should either be non-zero or the stream must be seekable.
//
// Example usage:
//
//	vaasClient := vaas.New(options, "wss://example.authentication.endpoint")
//	ctx := context.Background()
//	contentLength := 1234
//	verdict, err := vaasClient.ForStream(ctx, stream, contentLength)
//	if err != nil {
//	    log.Fatalf("Failed to get verdict: %v", err)
//	}
//	fmt.Printf("Verdict: %s\n", verdict.Verdict)
//	fmt.Printf("SHA256: %s\n", verdict.Sha256)
func (v *vaas) ForStream(ctx context.Context, stream io.Reader, contentLength int64) (msg.VaasVerdict, error) {
	request := msg.NewVerdictRequestForStream("", v.options)

	responseChan := v.openRequest(request)
	defer v.closeRequest(request)

	var response msg.VerdictResponse
	select {
	case response = <-responseChan:
	case <-ctx.Done():
		return msg.VaasVerdict{}, ctx.Err()
	}

	if response.Verdict != "" && response.Verdict != msg.Unknown {
		return msg.VaasVerdict{}, errors.New("server returned verdict without receiving content")
	}

	if len(strings.TrimSpace(response.UploadToken)) == 0 {
		return msg.VaasVerdict{}, errors.New("verdictResponse missing UploadToken for stream upload")
	}

	if len(strings.TrimSpace(response.URL)) == 0 {
		return msg.VaasVerdict{}, errors.New("verdictResponse missing URL for stream upload")
	}

	if err := v.uploadFile(stream, contentLength, response.URL, response.UploadToken); err != nil {
		return msg.VaasVerdict{
			Verdict: msg.Error,
			ErrMsg:  err.Error(),
		}, err
	}
	response = <-responseChan

	return msg.VaasVerdict{
		Verdict:   response.Verdict,
		Sha256:    response.Sha256,
		Detection: response.Detection,
		MimeType:  response.MimeType,
		FileType:  response.FileType,
	}, nil
}

func (v *vaas) forFileWithSha(ctx context.Context, data io.Reader, sha256 string) (msg.VaasVerdict, error) {
	request := msg.NewVerdictRequest("", v.options, sha256)
	responseChan := v.openRequest(request)
	defer v.closeRequest(request)

	var response msg.VerdictResponse
	select {
	case response = <-responseChan:
	case <-ctx.Done():
		return msg.VaasVerdict{}, ctx.Err()
	}

	if response.Verdict == msg.Unknown {
		if err := v.uploadFile(data, 0, response.URL, response.UploadToken); err != nil {
			return msg.VaasVerdict{
				Verdict: msg.Error,
				Sha256:  sha256,
				ErrMsg:  err.Error(),
			}, err
		}
		response = <-responseChan
	}

	return msg.VaasVerdict{
		Verdict:   response.Verdict,
		Sha256:    response.Sha256,
		Detection: response.Detection,
		FileType:  response.FileType,
		MimeType:  response.MimeType,
	}, nil
}

func (v *vaas) openRequest(request msg.VerdictRequest) <-chan msg.VerdictResponse {
	if v.options.EnableLogs {
		v.logger.Printf("Opening request for %s", request.GetRequestId())
	}

	v.openRequestsMutex.Lock()
	resultChan := make(chan msg.VerdictResponse, 1)
	v.openRequests[request.GetRequestId()] = resultChan
	v.openRequestsMutex.Unlock()
	if v.options.EnableLogs {
		v.logger.Printf("Opening new request: %v", request)
	}
	v.requestChannel <- request
	return resultChan
}

func (v *vaas) closeRequest(request msg.VerdictRequest) {
	if v.options.EnableLogs {
		v.logger.Printf("Closing request for %s", request.GetRequestId())
	}

	v.openRequestsMutex.Lock()
	close(v.openRequests[request.GetRequestId()])
	delete(v.openRequests, request.GetRequestId())
	v.openRequestsMutex.Unlock()
}

func (v *vaas) uploadFile(file io.Reader, contentLength int64, url string, token string) error {
	req, err := http.NewRequest(http.MethodPut, url, file)
	if err != nil {
		return err
	}

	if contentLength > 0 {
		req.ContentLength = contentLength
	} else {
		// VAAS requires a set Content-Length.
		// Here can add support for various io.Reader, which are not supported by the http package.
		if req.ContentLength == 0 {
			switch t := file.(type) {
			case io.Seeker:
				var size int64
				if size, err = t.Seek(0, io.SeekEnd); err == nil {
					if _, err = t.Seek(0, io.SeekStart); err == nil {
						req.ContentLength = size
						break
					}
				}
				return err
			default:
				return ErrUnsupportedReader
			}
		}
	}

	req.Header.Add("Authorization", token)

	client := http.Client{
		Transport: &http.Transport{
			TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
		},
	}
	httpResponse, err := client.Do(req)

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

// A goroutine running writePump is started for each connection. The
// application ensures that there is at most one writer to a connection by
// executing all writes from this goroutine.
// see https://github.com/Noooste/websocket/blob/master/examples/chat/client.go
func (v *vaas) writePump(websocketConnection websocketConnection, requestChannel chan msg.VerdictRequest) <-chan error {
	errorChan := make(chan error, 1)

	fmt.Printf("Starting writePump\n")

	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
	}()

	go func() {
		defer close(errorChan)
		for {
			select {
			case request, ok := <-requestChannel:
				if !ok {
					fmt.Printf("writePump leaving now\n")
					return
				}
				if err := websocketConnection.WriteJSON(request); err != nil {
					if v.options.EnableLogs {
						v.logger.Printf("Failed to send request %v", err)
					}
					errorChan <- errors.Join(errors.New("writing to websocket failed"), err)
					return
				}
			case <-ticker.C:
				err := websocketConnection.SetWriteDeadline(time.Now().Add(writeWait))
				if err != nil {
					errorChan <- err
					return
				}
				if err := websocketConnection.WriteMessage(websocket.PingMessage, nil); err != nil {
					errorChan <- errors.Join(errors.New("writing to websocket failed"), err)
					return
				}
			}
		}
	}()
	return errorChan
}

func (v *vaas) readPump(websocketConnection websocketConnection) <-chan error {
	errorChan := make(chan error, 1)

	if err := websocketConnection.SetReadDeadline(time.Now().Add(pongWait)); err != nil {
		errorChan <- err
		return errorChan
	}
	websocketConnection.SetPongHandler(func(string) error {
		return websocketConnection.SetReadDeadline(time.Now().Add(pongWait))
	})

	go func() {
		fmt.Printf("Starting readPump\n")
		defer fmt.Printf("Terminating readPump\n")

		defer close(errorChan)

		for {
			var verdictResponse msg.VerdictResponse

			err := websocketConnection.ReadJSON(&verdictResponse)
			if err == nil {
				v.openRequestsMutex.Lock()
				requestChan, exists := v.openRequests[verdictResponse.GUID]
				v.openRequestsMutex.Unlock()

				if exists {
					requestChan <- verdictResponse
				} else {
					if v.options.EnableLogs {
						v.logger.Printf("Received response for missing map entry - sha256: %s, guid: %s", verdictResponse.Sha256, verdictResponse.GUID)
					}
				}
				continue
			}

			// Error handling
			// websocket closed: end go routine
			// other errors: write to errorChan

			var closeErr *websocket.CloseError
			// If websocket was shutdownOnce by the server
			if errors.As(err, &closeErr) {
				switch closeErr.Code {
				case websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseNoStatusReceived:
					if v.options.EnableLogs {
						v.logger.Printf("Websocket shutdownOnce - %d: %s", closeErr.Code, closeErr.Text)
					}
					errorChan <- closeErr
					return
				default:
					errorChan <- fmt.Errorf("unexpected shutdownOnce of websocket - %w", closeErr)
					return
				}
			}
			// This error occurs when the context is canceled and we call close() on the websocket connection.
			if errors.Is(err, net.ErrClosed) {
				if v.options.EnableLogs {
					v.logger.Printf("Websocket connection was closed")
				}
				errorChan <- err
				return
			}
			// This error occurs if whe JSON response could not be parsed by the websocket.
			if errors.Is(err, io.ErrUnexpectedEOF) {
				if v.options.EnableLogs {
					v.logger.Printf("Temporarily failed to read from websocket: %v", err)
				}
				continue
			}
			// We don't know what happened here, help...
			if v.options.EnableLogs {
				v.logger.Printf("Permanently failed to read from websocket: %v", err)
			}
			errorChan <- fmt.Errorf("unexpected error of websocket connection - %w", err)
			return
		}
	}()

	return errorChan
}

func (v *vaas) failAllOpenRequests(err error) {
	v.openRequestsMutex.Lock()
	defer v.openRequestsMutex.Unlock()

	for _, request := range v.openRequests {
		// TODO: Refactor to include proper error message here
		request <- msg.VerdictResponse{
			Verdict: msg.Error,
		}
	}
}

func (v *vaas) connectLoop() error {
	var terminate = false
	var err error
	for !terminate {
		fmt.Printf("connectLoop new iteration\n")
		// TODO: handle error
		err = func() error {
			var reconnect = false

			// TODO: timeout for connect and auth
			connection, response, err := websocket.DefaultDialer.DialContext(context.TODO(), v.vaasURL, nil, nil)
			if errors.Is(err, websocket.ErrBadHandshake) {
				return fmt.Errorf("handshake failed with status {%d}", response.StatusCode)
			}
			if err != nil {
				return err
			}

			var token string
			if token, err = v.authenticator.GetToken(); err != nil {
				return err
			}

			connection.SetWriteDeadline(time.Now().Add(writeWait))
			if err = connection.WriteJSON(msg.AuthRequest{
				Kind:  "AuthRequest",
				Token: token,
			}); err != nil {
				return err
			}

			connection.SetReadDeadline(time.Now().Add(pongWait))
			var authResponse msg.AuthResponse
			if err = connection.ReadJSON(&authResponse); err != nil {
				return err
			}
			if authResponse.Kind == "Error" {
				return errors.New(authResponse.Text)
			}
			if !authResponse.Success {
				return errors.New("failed to authenticate")
			}

			sessionID := authResponse.SessionID

			fmt.Printf("New authenticated connection established: %s\n", sessionID)

			readErrChan := v.readPump(connection)

			writeChan := make(chan msg.VerdictRequest, 1)
			writeErrChan := v.writePump(connection, writeChan)

			for !reconnect && !terminate {
				select {
				case request, ok := <-v.requestChannel:
					if !ok {
						fmt.Printf("request channel closed, terminating\n")
						terminate = true
						break
					}
					request.SetSessionId(sessionID)
					fmt.Printf("forwarding request to writePump\n")
					writeChan <- request
					break
				case err, ok := <-readErrChan:
					reconnect = true
					if !ok {
						err = errors.New("readPump closed without error message")
					}
					return err
				case err, ok := <-writeErrChan:
					reconnect = true
					if !ok {
						err = errors.New("writePump closed without error message")
					}
					return err
				}
			}

			close(writeChan)
			<-writeErrChan
			err = connection.Close()
			<-readErrChan
			fmt.Printf("Shutdown completed\n")

			// fail remaining requests
			return err
		}()
		if v.options.EnableLogs {
			v.logger.Printf("Connection error: %v\n", err)
		}
		v.failAllOpenRequests(err)
	}
	close(v.connectionLoopTermChan)
	return err
}
