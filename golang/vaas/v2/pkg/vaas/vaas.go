// Package vaas provides a client for interacting with G DATA CyberDefense's VaaS Service
// for sending analysis requests to the Vaas server for various types of data, such as URLs, SHA256 hashes, and files.
package vaas

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/v2/pkg/authenticator"
	msg "github.com/GDATASoftwareAG/vaas/golang/vaas/v2/pkg/messages"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/v2/pkg/options"
	"io"
	"net/http"
	"net/url"
)

// Vaas provides various ForXXX-functions to send analysis requests to a VaaS server.
// All kinds of requests can be canceled by the context.
// The Connect() function has to be called before any other requests are made.
// Please refer to the individual function comments for more details on their usage and behavior.
type Vaas interface {
	ForUrl(ctx context.Context, uri string) (msg.VaasVerdict, error)
	ForStream(ctx context.Context, stream io.Reader, contentLength int64) (msg.VaasVerdict, error)
	ForSha256(ctx context.Context, sha256 string) (msg.VaasVerdict, error)
	ForFile(ctx context.Context, path string) (msg.VaasVerdict, error)
	ForFileInMemory(ctx context.Context, file io.Reader) (msg.VaasVerdict, error)
}

var (
	ErrUnsupportedReader = errors.New("unsupported reader")
)

// vaas provides the implementation of the Vaas interface.
type vaas struct {
	vaasURL       *url.URL
	options       options.VaasOptions
	authenticator authenticator.Authenticator
}

// New creates a new instance of the Vaas struct, which represents a client for interacting with a Vaas service.
// The vaasURL parameter specifies the endpoint for the VaaS service.
func New(options options.VaasOptions, vaasURL *url.URL, authenticator authenticator.Authenticator) Vaas {
	client := &vaas{
		options:       options,
		vaasURL:       vaasURL,
		authenticator: authenticator,
	}
	return client
}

// NewWithDefaultEndpoint creates a new instance of the Vaas struct with a default endpoint.
// It represents a client for interacting with a Vaas service.
func NewWithDefaultEndpoint(options options.VaasOptions, authenticator authenticator.Authenticator) Vaas {
	vaasURL, _ := url.Parse("wss://gateway.production.vaas.gdatasecurity.de")
	return New(options, vaasURL, authenticator)
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
	// Loop until we get 200 or an error
	for {
		token, err := v.authenticator.GetToken()
		if err != nil {
			return msg.VaasVerdict{}, err
		}

		reportUrl, err := url.JoinPath(v.vaasURL.String(), "files", sha256, "report")

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reportUrl, nil)
		if err != nil {
			return msg.VaasVerdict{}, err
		}
		req.Header.Add("Authorization", "Bearer "+token)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return msg.VaasVerdict{}, err
		}
		defer func() {
			// TODO: Handle error?
			_ = resp.Body.Close()
		}()

		switch resp.StatusCode {
		case http.StatusNotFound:
			return msg.VaasVerdict{
				Verdict: msg.Unknown,
				Sha256:  sha256,
			}, nil
		case http.StatusAccepted:
			continue
		case http.StatusOK:
			var report msg.VaasReport

			err := json.NewDecoder(resp.Body).Decode(&report)
			if err != nil {
				return msg.VaasVerdict{}, err
			}

			return report.ConvertToVaasVerdict(), nil
		default:
			return msg.VaasVerdict{}, fmt.Errorf("received non-200 status code %d", resp.StatusCode)
		}
	}
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
	return msg.VaasVerdict{}, errors.New("not implemented")
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
	return msg.VaasVerdict{}, errors.New("not implemented")
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
	return msg.VaasVerdict{}, errors.New("not implemented")
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
	return msg.VaasVerdict{}, errors.New("not implemented")
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
