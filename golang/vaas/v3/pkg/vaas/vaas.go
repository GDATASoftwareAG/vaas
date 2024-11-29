// Package vaas provides a client for interacting with G DATA CyberDefense's VaaS Service
// for sending analysis requests to the Vaas server for various types of data, such as URLs, SHA256 hashes, and files.
package vaas

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"github.com/GDATASoftwareAG/vaas/golang/vaas/v3/internal/hash"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/v3/pkg/authenticator"
	msg "github.com/GDATASoftwareAG/vaas/golang/vaas/v3/pkg/messages"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/v3/pkg/options"
)

const (
	userAgent = "Go/3.0.10-alpha"
)

// Errors returned by the VaaS API
var (
	ErrVaasClient         = errors.New("client error")
	ErrVaasServer         = errors.New("server reported an internal error")
	ErrVaasAuthentication = errors.New("VaaS authentication failed")
	ErrVaasConnection     = errors.New("could not connect to VaaS")
)

// Vaas provides various ForXXX-functions to send analysis requests to a VaaS server.
// All kinds of requests can be canceled by the context.
// Please refer to the individual function comments for more details on their usage and behavior.
type Vaas interface {
	ForSha256(ctx context.Context, sha256 string, options *options.ForSha256Options) (msg.VaasVerdict, error)
	ForFile(ctx context.Context, path string, options *options.ForFileOptions) (msg.VaasVerdict, error)
	ForUrl(ctx context.Context, url *url.URL, options *options.ForUrlOptions) (msg.VaasVerdict, error)
	ForStream(ctx context.Context, stream io.Reader, contentLength int64, options *options.ForStreamOptions) (msg.VaasVerdict, error)
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
	err := msg.UnmarshalAndValidate(responseBody, &problemDetails)
	var baseErr error
	if err != nil {
		statusCode := response.StatusCode
		switch {
		case statusCode == 401:
			baseErr = ErrVaasAuthentication
		case statusCode >= 400 && statusCode < 500:
			baseErr = ErrVaasClient
		case statusCode >= 500:
			baseErr = ErrVaasServer
		default:
			baseErr = ErrVaasServer
		}
		// Server did not reply with a parseable error body, returning the HTTP code instead
		return errors.Join(baseErr, errors.New("HTTP error: "+response.Status))
	}

	switch problemDetails.Type {
	case "VaasClientException":
		baseErr = ErrVaasClient
	case "VaasServerException":
		baseErr = ErrVaasServer
	default:
		baseErr = ErrVaasServer
	}
	return errors.Join(baseErr, errors.New(problemDetails.Detail))
}

func readHttpResponse(httpClient *http.Client, request *http.Request) (Response *http.Response, Body []byte, Error error) {
	resp, err := httpClient.Do(request)
	if err != nil {
		return nil, nil, errors.Join(ErrVaasConnection, err)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, nil, errors.Join(ErrVaasClient, err)
	}
	err = resp.Body.Close()
	if err != nil {
		return resp, data, errors.Join(ErrVaasClient, err)
	}
	return resp, data, nil
}

func encodeToJsonBuffer(data any) (*bytes.Buffer, error) {
	encoded, err := json.Marshal(data)
	if err != nil {
		return nil, errors.Join(ErrVaasClient, err)
	}
	return bytes.NewBuffer(encoded), nil
}

func (v *vaas) newAuthenticatedRequest(ctx context.Context, method string, url string, body io.Reader) (*http.Request, error) {
	token, err := v.authenticator.GetToken()
	if err != nil {
		return nil, errors.Join(ErrVaasAuthentication, err)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, errors.Join(ErrVaasClient, err)
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
		return analysis, errors.Join(ErrVaasClient, err)
	}
	return analysis, nil
}

func (v *vaas) uploadFile(ctx context.Context, file io.Reader, contentLength int64) (msg.FileAnalysis, error) {
	var analysis = msg.FileAnalysis{}
	uploadUrl := v.vaasURL.JoinPath("files")
	params := url.Values{}
	params.Add("useHashLookup", strconv.FormatBool(v.options.UseHashLookup))
	uploadUrl.RawQuery = params.Encode()
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
		return analysis, errors.Join(ErrVaasClient, err)
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
			return nil, errors.Join(ErrVaasClient, fmt.Errorf("url job %v not found", urlJobId))
		case http.StatusAccepted:
			continue
		case http.StatusOK:
			var report msg.URLReport
			err := json.Unmarshal(body, &report)
			if err != nil {
				return nil, errors.Join(ErrVaasClient, err)
			}
			return &report, nil
		default:
			return nil, parseVaasError(response, body)
		}
	}
}

func (v *vaas) pollFileReport(ctx context.Context, sha256 string, opts *options.ForSha256Options) (*msg.FileReport, error) {
	reportUrl := v.vaasURL.JoinPath("files", sha256, "report")
	params := url.Values{}
	params.Add("useCache", strconv.FormatBool(opts.UseCache))
	params.Add("useHashLookup", strconv.FormatBool(opts.UseHashLookup))
	reportUrl.RawQuery = params.Encode()
	reportUrlString := reportUrl.String()
	// Loop until we get 200 or an error
	for {
		req, err := v.newAuthenticatedRequest(ctx, http.MethodGet, reportUrlString, nil)
		if err != nil {
			return nil, err
		}

		if opts.VaasRequestId != "" {
			req.Header.Add("tracestate", fmt.Sprintf("vaasrequestid=%v", opts.VaasRequestId))
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
				return nil, errors.Join(ErrVaasClient, err)
			}
			return &report, nil
		default:
			return nil, parseVaasError(response, body)
		}
	}
}

// ForSha256 sends an analysis request for a file identified by its SHA256 hash to the VaaS server and returns the verdict.
// The analysis can be canceled using the provided context.
//
// Example usage:
//
//	vaasClient := vaas.NewWithDefaultEndpoint(options, auth)
//	ctx := context.Background()
//	sha256 := "..."
//	verdict, err := vaasClient.ForSha256(ctx, sha256)
//	if err != nil {
//	    log.Fatalf("Failed to get verdict: %v", err)
//	}
//	fmt.Printf("Verdict: %s\n", verdict.Verdict)
//	fmt.Printf("SHA256: %s\n", verdict.Sha256)
func (v *vaas) ForSha256(ctx context.Context, sha256 string, opts *options.ForSha256Options) (msg.VaasVerdict, error) {
	if opts == nil {
		opts = &options.ForSha256Options{}
	}

	report, err := v.pollFileReport(ctx, sha256, opts)
	if err != nil {
		return msg.VaasVerdict{}, err
	}

	if report == nil {
		// Not found
		return msg.VaasVerdict{
			Verdict: msg.Unknown,
			Sha256:  sha256,
		}, nil
	}
	return report.ConvertToVaasVerdict(), nil
}

// ForFile sends an analysis request for a file at the given filePath to the VaaS server and returns the verdict.
// The analysis can be canceled using the provided context.
//
// Example usage:
//
//	vaasClient := vaas.NewWithDefaultEndpoint(options, auth)
//	ctx := context.Background()
//	filePath := "path/to/file.txt"
//	verdict, err := vaasClient.ForFile(ctx, filePath)
//	if err != nil {
//	    log.Fatalf("Failed to get verdict: %v", err)
//	}
//	fmt.Printf("Verdict: %s\n", verdict.Verdict)
//	fmt.Printf("SHA256: %s\n", verdict.Sha256)
func (v *vaas) ForFile(ctx context.Context, filePath string, options *options.ForFileOptions) (msg.VaasVerdict, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return msg.VaasVerdict{}, errors.Join(ErrVaasClient, err)
	}
	defer func() {
		_ = file.Close()
	}()

	sha256, err := hash.CalculateSha256(file)
	if err != nil {
		return msg.VaasVerdict{}, errors.Join(ErrVaasClient, err)
	}

	verdict, err := v.ForSha256(ctx, sha256, nil)
	// We only care about the hash lookup if it's not failed and has actionable verdict
	if err == nil && verdict.Verdict != msg.Unknown {
		return verdict, nil
	}

	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return msg.VaasVerdict{}, errors.Join(ErrVaasClient, err)
	}

	stat, err := file.Stat()
	if err != nil {
		return msg.VaasVerdict{}, errors.Join(ErrVaasClient, err)
	}

	return v.ForStream(ctx, file, stat.Size(), nil)
}

// ForUrl sends an analysis request for a file URL to the VaaS server and returns the verdict.
// The analysis can be canceled using the provided context.
//
// Example usage:
//
//	vaasClient := vaas.NewWithDefaultEndpoint(options, auth)
//	ctx := context.Background()
//	myUrl, _ := url.Parse("https://example.com/examplefile")
//	verdict, err := vaasClient.ForUrl(ctx, myUrl)
//	if err != nil {
//	    log.Fatalf("Failed to get verdict: %v", err)
//	}
//	fmt.Printf("Verdict: %s\n", verdict.Verdict)
//	fmt.Printf("SHA256: %s\n", verdict.Sha256)
func (v *vaas) ForUrl(ctx context.Context, url *url.URL, options *options.ForUrlOptions) (msg.VaasVerdict, error) {
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

// ForStream sends an analysis request for a file stream to the VaaS server and returns the verdict.
// contentLength must be set to the stream's length, in bytes.
// The analysis can be canceled using the provided context.
//
// Example usage:
//
//	vaasClient := vaas.NewWithDefaultEndpoint(options, auth)
//	ctx := context.Background()
//	contentLength := 1234
//	verdict, err := vaasClient.ForStream(ctx, stream, contentLength)
//	if err != nil {
//	    log.Fatalf("Failed to get verdict: %v", err)
//	}
//	fmt.Printf("Verdict: %s\n", verdict.Verdict)
//	fmt.Printf("SHA256: %s\n", verdict.Sha256)
func (v *vaas) ForStream(ctx context.Context, stream io.Reader, contentLength int64, options *options.ForStreamOptions) (msg.VaasVerdict, error) {
	analysis, err := v.uploadFile(ctx, stream, contentLength)
	if err != nil {
		return msg.VaasVerdict{}, err
	}

	return v.ForSha256(ctx, analysis.Sha256, nil)
}
