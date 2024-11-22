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
	"strings"
)

// TODO: useCache, useHashLookup ???

const (
	userAgent = "Go/3.0.8-alpha"
)

// Errors returned by the VaaS API
var (
	ErrClientFailure         = errors.New("client error")
	ErrServerFailure         = errors.New("server error")
	ErrAuthenticationFailure = errors.New("authentication failed")
)

// Vaas provides various ForXXX-functions to send analysis requests to a VaaS server.
// All kinds of requests can be canceled by the context.
// Please refer to the individual function comments for more details on their usage and behavior.
type Vaas interface {
	ForUrl(ctx context.Context, url url.URL) (msg.VaasVerdict, error)
	ForStream(ctx context.Context, stream io.Reader, contentLength int64) (msg.VaasVerdict, error)
	ForSha256(ctx context.Context, sha256 string) (msg.VaasVerdict, error)
	ForFile(ctx context.Context, path string) (msg.VaasVerdict, error)
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
		return nil, nil, err
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, nil, err
	}
	err = resp.Body.Close()
	if err != nil {
		return resp, data, err
	}
	return resp, data, nil
}

func encodeToJsonBuffer(data any) (*bytes.Buffer, error) {
	encoded, err := json.Marshal(data)
	if err != nil {
		return nil, err
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
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("User-Agent", userAgent)
	return req, nil
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
	// Loop until we get 200 or an error
	for {
		select {
		case <-ctx.Done():
			return msg.VaasVerdict{}, ctx.Err()
		default:
		}

		reportUrl := v.vaasURL.JoinPath("files", sha256, "report").String()
		req, err := v.newAuthenticatedRequest(ctx, http.MethodGet, reportUrl, nil)
		if err != nil {
			return msg.VaasVerdict{}, err
		}

		response, body, err := readHttpResponse(v.httpClient, req)
		if err != nil {
			return msg.VaasVerdict{}, err
		}

		switch response.StatusCode {
		case http.StatusNotFound:
			return msg.VaasVerdict{
				Verdict: msg.Unknown,
				Sha256:  sha256,
			}, nil
		case http.StatusAccepted:
			continue
		case http.StatusOK:
			var report msg.FileReport

			err := json.Unmarshal(body, &report)
			if err != nil {
				return msg.VaasVerdict{}, err
			}

			return report.ConvertToVaasVerdict(), nil
		default:
			return msg.VaasVerdict{}, parseVaasError(response, body)
		}
	}
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
		return msg.VaasVerdict{}, err
	}
	defer func() {
		_ = file.Close()
	}()

	sha256, err := hash.CalculateSha256(file)
	if err != nil {
		return msg.VaasVerdict{}, err
	}
	verdict, err := v.ForSha256(ctx, sha256)
	if err != nil {
		return msg.VaasVerdict{}, err
	}

	if verdict.Verdict != msg.Unknown {
		return verdict, nil
	}

	if _, err = file.Seek(0, 0); err != nil {
		return msg.VaasVerdict{}, err
	}

	stat, err := file.Stat()
	if err != nil {
		return msg.VaasVerdict{}, err
	}

	return v.ForStream(ctx, file, stat.Size())
}

// TODO: return the parsed body (TBD how API will look)
func (v *vaas) upload(ctx context.Context, file io.Reader, contentLength int64) (string, error) {
	uploadUrl := v.vaasURL.JoinPath("files").String()
	req, err := v.newAuthenticatedRequest(ctx, http.MethodPut, uploadUrl, file)
	if err != nil {
		return "", err
	}
	req.ContentLength = contentLength
	response, body, err := readHttpResponse(v.httpClient, req)
	if err != nil {
		return "", err
	}

	if response.StatusCode != http.StatusCreated {
		return "", parseVaasError(response, body)
	}

	location := response.Header.Get("Location")
	prefix := "/files/"
	if !strings.HasPrefix(location, prefix) {
		return "", errors.Join(ErrServerFailure, errors.New("can't parse Location in response"))
	}
	sha256 := strings.TrimPrefix(location, prefix)
	return sha256, nil
}

func (v *vaas) submitUrlForAnalysis(ctx context.Context, url url.URL) (msg.URLAnalysis, error) {
	var analysis = msg.URLAnalysis{}
	submitUrl := v.vaasURL.JoinPath("urls").String()
	var analysisRequest = msg.URLAnalysisRequest{
		Url: url.String(),
		// TODO
		UseHashLookup: true,
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
	return analysis, err
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
			return nil, errors.Join(ErrServerFailure, errors.New("url job not found"))
		case http.StatusAccepted:
			continue
		case http.StatusOK:
			var report msg.URLReport

			err := json.Unmarshal(body, &report)
			if err != nil {
				return nil, err
			}

			return &report, nil
		default:
			return nil, parseVaasError(response, body)
		}
	}
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
func (v *vaas) ForUrl(ctx context.Context, url url.URL) (msg.VaasVerdict, error) {
	analysis, err := v.submitUrlForAnalysis(ctx, url)
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
	sha256, err := v.upload(ctx, stream, contentLength)
	if err != nil {
		return msg.VaasVerdict{}, err
	}

	return v.ForSha256(ctx, sha256)
}
