// Package vaas provides a client for interacting with G DATA CyberDefense's VaaS Service
// for sending analysis requests to the Vaas server for various types of data, such as URLs, SHA256 hashes, and files.
package vaas

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/v3/internal/hash"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/v3/pkg/authenticator"
	msg "github.com/GDATASoftwareAG/vaas/golang/vaas/v3/pkg/messages"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/v3/pkg/options"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
)

const (
	userAgent = "Go/3.0.8-alpha"
)

// Errors returned by the VaaS API
var (
	ErrClientFailure         = errors.New("client error")
	ErrServerFailure         = errors.New("server reported an internal error")
	ErrAuthenticationFailure = errors.New("VaaS authentication failed")
	ErrConnectionProblem     = errors.New("could not connect to VaaS")
)

// Vaas provides various ForXXX-functions to send analysis requests to a VaaS server.
// All kinds of requests can be canceled by the context.
// Please refer to the individual function comments for more details on their usage and behavior.
type Vaas interface {
	ForUrl(ctx context.Context, url *url.URL) (msg.VaasVerdict, error)
	ForStream(ctx context.Context, stream io.Reader, contentLength int64) (msg.VaasVerdict, error)
	ForSha256(ctx context.Context, sha256 string) (msg.VaasVerdict, error)
	ForFile(ctx context.Context, path string) (msg.VaasVerdict, error)
	SetOptions(options options.VaasOptions)
}

// vaas provides the implementation of the Vaas interface.
type vaas struct {
	vaasURL       *url.URL
	options       options.VaasOptions
	authenticator authenticator.Authenticator
	httpClient    *http.Client
}

// New creates a new instance of the Vaas struct, which represents a client for interacting with a Vaas service.
// The vaasURL parameter specifies the endpoint for the VaaS service.
func New(options options.VaasOptions, vaasURL *url.URL, authenticator authenticator.Authenticator) Vaas {
	client := &vaas{
		options:       options,
		vaasURL:       vaasURL,
		authenticator: authenticator,
		httpClient: &http.Client{
			Transport: &http.Transport{
				// Disable HTTP/2
				TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
			},
		},
	}
	return client
}

// NewWithDefaultEndpoint creates a new instance of the Vaas struct with a default endpoint.
// It represents a client for interacting with a Vaas service.
func NewWithDefaultEndpoint(options options.VaasOptions, authenticator authenticator.Authenticator) Vaas {
	vaasURL, _ := url.Parse("https://gateway.production.vaas.gdatasecurity.de")
	return New(options, vaasURL, authenticator)
}

func parseVaasError(response *http.Response, responseBody []byte) error {
	var problemDetails msg.ProblemDetails
	err := json.Unmarshal(responseBody, &problemDetails)
	if err != nil {
		// Server did not reply with a parseable error body, returning the HTTP code instead
		return errors.Join(ErrServerFailure, errors.New("HTTP error: "+response.Status))
	}

	var baseErr error
	switch problemDetails.Type {
	case "VaasClientException":
		baseErr = ErrClientFailure
	case "VaasServerException":
		baseErr = ErrServerFailure
	default:
		baseErr = ErrServerFailure
	}
	return errors.Join(baseErr, errors.New(problemDetails.Detail))
}

func readHttpResponse(httpClient *http.Client, request *http.Request) (Response *http.Response, Body []byte, Error error) {
	resp, err := httpClient.Do(request)
	if err != nil {
		return nil, nil, errors.Join(ErrConnectionProblem, err)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, nil, errors.Join(ErrClientFailure, err)
	}
	err = resp.Body.Close()
	if err != nil {
		return resp, data, errors.Join(ErrClientFailure, err)
	}
	return resp, data, nil
}

func encodeToJsonBuffer(data any) (*bytes.Buffer, error) {
	encoded, err := json.Marshal(data)
	if err != nil {
		return nil, errors.Join(ErrClientFailure, err)
	}
	return bytes.NewBuffer(encoded), nil
}

func (v *vaas) newAuthenticatedRequest(ctx context.Context, method string, url string, body io.Reader) (*http.Request, error) {
	token, err := v.authenticator.GetToken()
	if err != nil {
		return nil, errors.Join(ErrAuthenticationFailure, err)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, errors.Join(ErrClientFailure, err)
	}
	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("User-Agent", userAgent)
	return req, nil
}

func (v *vaas) uploadUrl(ctx context.Context, url *url.URL) (msg.URLAnalysis, error) {
	var analysis = msg.URLAnalysis{}
	submitUrl := v.vaasURL.JoinPath("urls").String()
	var analysisRequest = msg.URLAnalysisRequest{
		Url:           url.String(),
		UseHashLookup: v.options.UseHashLookup,
	}
	buffer, err := encodeToJsonBuffer(&analysisRequest)
	if err != nil {
		return analysis, err
	}
	req, err := v.newAuthenticatedRequest(ctx, http.MethodPost, submitUrl, buffer)
	if err != nil {
		return analysis, err
	}
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	response, body, err := readHttpResponse(v.httpClient, req)
	if err != nil {
		return analysis, err
	}

	if response.StatusCode != http.StatusCreated {
		return analysis, parseVaasError(response, body)
	}

	err = json.Unmarshal(body, &analysis)
	if err != nil {
		return analysis, errors.Join(ErrClientFailure, err)
	}
	return analysis, nil
}

func (v *vaas) uploadFile(ctx context.Context, file io.Reader, contentLength int64) (msg.FileAnalysis, error) {
	var analysis = msg.FileAnalysis{}
	uploadUrl := v.vaasURL.JoinPath("files")
	uploadUrl.Query().Add("useHashLookup", strconv.FormatBool(v.options.UseHashLookup))
	req, err := v.newAuthenticatedRequest(ctx, http.MethodPost, uploadUrl.String(), file)
	if err != nil {
		return analysis, err
	}
	req.ContentLength = contentLength
	response, body, err := readHttpResponse(v.httpClient, req)
	if err != nil {
		return analysis, err
	}

	if response.StatusCode != http.StatusCreated {
		return analysis, parseVaasError(response, body)
	}

	err = json.Unmarshal(body, &analysis)
	if err != nil {
		return analysis, errors.Join(ErrClientFailure, err)
	}
	return analysis, nil
}

func (v *vaas) pollUrlJob(ctx context.Context, urlJobId string) (*msg.URLReport, error) {
	submitUrl := v.vaasURL.JoinPath("urls", urlJobId, "report").String()
	// Loop until 200 or error
	for {
		req, err := v.newAuthenticatedRequest(ctx, http.MethodGet, submitUrl, nil)
		if err != nil {
			return nil, err
		}
		response, body, err := readHttpResponse(v.httpClient, req)
		if err != nil {
			return nil, err
		}

		switch response.StatusCode {
		case http.StatusNotFound:
			return nil, errors.Join(ErrClientFailure, errors.New("url job not found"))
		case http.StatusAccepted:
			continue
		case http.StatusOK:
			var report msg.URLReport
			err := json.Unmarshal(body, &report)
			if err != nil {
				return nil, errors.Join(ErrClientFailure, err)
			}
			return &report, nil
		default:
			return nil, parseVaasError(response, body)
		}
	}
}

func (v *vaas) pollFile(ctx context.Context, sha256 string) (*msg.FileReport, error) {
	reportUrl := v.vaasURL.JoinPath("files", sha256, "report")
	reportUrl.Query().Add("useHashLookup", strconv.FormatBool(v.options.UseHashLookup))
	reportUrl.Query().Add("useCache", strconv.FormatBool(v.options.UseCache))
	reportUrlString := reportUrl.String()
	// Loop until we get 200 or an error
	for {
		req, err := v.newAuthenticatedRequest(ctx, http.MethodGet, reportUrlString, nil)
		if err != nil {
			return nil, err
		}

		response, body, err := readHttpResponse(v.httpClient, req)
		if err != nil {
			return nil, err
		}

		switch response.StatusCode {
		case http.StatusNotFound:
			return nil, nil
		case http.StatusAccepted:
			continue
		case http.StatusOK:
			var report msg.FileReport
			err = json.Unmarshal(body, &report)
			if err != nil {
				return nil, errors.Join(ErrClientFailure, err)
			}
			return &report, nil
		default:
			return nil, parseVaasError(response, body)
		}
	}
}

// ForSha256 sends an analysis request for a file identified by its SHA256 hash to the Vaas server and returns the verdict.
// The analysis can be canceled using the provided context.
//
// Example usage:
//
//	vaasClient := vaas.New(options, "https://example.authentication.endpoint")
//	ctx := context.Background()
//	sha256 := "..."
//	verdict, err := vaasClient.ForSha256(ctx, sha256)
//	if err != nil {
//	    log.Fatalf("Failed to get verdict: %v", err)
//	}
//	fmt.Printf("Verdict: %s\n", verdict.Verdict)
//	fmt.Printf("SHA256: %s\n", verdict.Sha256)
func (v *vaas) ForSha256(ctx context.Context, sha256 string) (msg.VaasVerdict, error) {
	report, err := v.pollFile(ctx, sha256)
	if err != nil {
		return msg.VaasVerdict{}, err
	}

	if report == nil {
		// Not found
		return msg.VaasVerdict{
			Verdict: msg.Unknown,
		}, nil
	}
	return report.ConvertToVaasVerdict(), nil
}

// ForFile sends an analysis request for a file at the given filePath to the Vaas server and returns the verdict.
// The analysis can be canceled using the provided context.
//
// Example usage:
//
//	vaasClient := vaas.New(options, "https://example.authentication.endpoint")
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
	if err != nil {
		return msg.VaasVerdict{}, errors.Join(ErrClientFailure, err)
	}
	defer func() {
		_ = file.Close()
	}()

	sha256, err := hash.CalculateSha256(file)
	if err != nil {
		return msg.VaasVerdict{}, errors.Join(ErrClientFailure, err)
	}
	verdict, err := v.ForSha256(ctx, sha256)
	if err != nil {
		return msg.VaasVerdict{}, err
	}

	if verdict.Verdict != msg.Unknown {
		return verdict, nil
	}

	if _, err = file.Seek(0, 0); err != nil {
		return msg.VaasVerdict{}, errors.Join(ErrClientFailure, err)
	}

	stat, err := file.Stat()
	if err != nil {
		return msg.VaasVerdict{}, errors.Join(ErrClientFailure, err)
	}

	return v.ForStream(ctx, file, stat.Size())
}

// ForUrl sends an analysis request for a file URL to the Vaas server and returns the verdict.
// The analysis can be canceled using the provided context.
//
// Example usage:
//
//	vaasClient := vaas.New(options, "https://example.authentication.endpoint")
//	ctx := context.Background()
//	verdict, err := vaasClient.ForUrl(ctx, "https://example.com/examplefile")
//	if err != nil {
//	    log.Fatalf("Failed to get verdict: %v", err)
//	}
//	fmt.Printf("Verdict: %s\n", verdict.Verdict)
//	fmt.Printf("SHA256: %s\n", verdict.Sha256)
func (v *vaas) ForUrl(ctx context.Context, url *url.URL) (msg.VaasVerdict, error) {
	analysis, err := v.uploadUrl(ctx, url)
	if err != nil {
		return msg.VaasVerdict{}, err
	}
	report, err := v.pollUrlJob(ctx, analysis.JobId)
	if err != nil {
		return msg.VaasVerdict{}, err
	}
	return report.ConvertToVaasVerdict(), nil
}

// ForStream sends an analysis request for a file stream to the Vaas server and returns the verdict.
// The analysis can be canceled using the provided context.
// ContentLength should either be non-zero or the stream must be seekable.
//
// Example usage:
//
//	vaasClient := vaas.New(options, "https://example.authentication.endpoint")
//	ctx := context.Background()
//	contentLength := 1234
//	verdict, err := vaasClient.ForStream(ctx, stream, contentLength)
//	if err != nil {
//	    log.Fatalf("Failed to get verdict: %v", err)
//	}
//	fmt.Printf("Verdict: %s\n", verdict.Verdict)
//	fmt.Printf("SHA256: %s\n", verdict.Sha256)
func (v *vaas) ForStream(ctx context.Context, stream io.Reader, contentLength int64) (msg.VaasVerdict, error) {
	analysis, err := v.uploadFile(ctx, stream, contentLength)
	if err != nil {
		return msg.VaasVerdict{}, err
	}

	return v.ForSha256(ctx, analysis.Sha256)
}

// SetOptions changes the request configuration. The new options will become effective for the next and subsequent requests.
func (v *vaas) SetOptions(options options.VaasOptions) {
	v.options = options
}
