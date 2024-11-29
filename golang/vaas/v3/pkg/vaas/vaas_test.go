package vaas

import (
	"context"
	"encoding/base64"
	"errors"
	"log"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GDATASoftwareAG/vaas/golang/vaas/v3/pkg/authenticator"
	msg "github.com/GDATASoftwareAG/vaas/golang/vaas/v3/pkg/messages"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/v3/pkg/options"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
)

type testFixture struct {
	vaasClient Vaas
	errorChan  <-chan error
}

const (
	eicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
)

func (tf *testFixture) setUp() Vaas {
	if err := godotenv.Load(); err != nil {
		log.Printf("failed to load environment - %v", err)
	}

	vaasURLString, exists := os.LookupEnv("VAAS_URL")
	if !exists {
		log.Fatal("no vaas endpoint configured")
	}

	return tf.setUpWithVaasURL(vaasURLString)
}

func (tf *testFixture) setUpWithVaasURL(vaasURLString string) Vaas {
	if err := godotenv.Load(); err != nil {
		log.Printf("failed to load environment - %v", err)
	}

	clientID, exists := os.LookupEnv("CLIENT_ID")
	if !exists {
		log.Fatal("no Client ID set")
	}
	clientSecret, exists := os.LookupEnv("CLIENT_SECRET")
	if !exists {
		log.Fatal("no Client Secret set")
	}
	vaasURL, err := url.Parse(vaasURLString)
	if err != nil {
		log.Fatal(err)
	}
	tokenEndpoint, exists := os.LookupEnv("TOKEN_URL")
	if !exists {
		log.Fatal("no token endpoint configured")
	}

	testingOptions := options.VaasOptions{
		UseHashLookup: true,
		UseCache:      false,
	}
	auth := authenticator.New(clientID, clientSecret, tokenEndpoint)
	tf.vaasClient = New(testingOptions, vaasURL, auth)

	return tf.vaasClient
}

// For all
//   _SendsUserAgent
//   _SendsOptions
//   _IfVaasRequestIdIsSet_SendsTraceState
//   _IfVaasClientException_ThrowsVaasClientException
//   _IfVaasServerException_ThrowsVaasServerException
//   _IfAuthenticatorThrowsAuthenticationException_ThrowsAuthenticationException
//   _If401_ThrowsAuthenticationException
//   _IfCancellationRequested_ThrowsOperationCancelledException

func TestVaas_ForSha256(t *testing.T) {
	const (
		cleanSha256     string = "cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e"
		maliciousSha256 string = "ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2"
		unknownSha256   string = "1f72c1111111111111f912e40b7323a0192a300b376186c10f6803dc5efe28df"
	)
	type args struct {
		sha256          string
		expectedVerdict msg.Verdict
	}
	tests := []struct {
		args          args
		name          string
		expectedError error
	}{
		{
			name: "With clean sha256 - got verdict clean",
			args: args{
				sha256:          cleanSha256,
				expectedVerdict: msg.Clean,
			},
		},
		{
			name: "With malicious sha256 - got verdict malicious",
			args: args{
				sha256:          maliciousSha256,
				expectedVerdict: msg.Malicious,
			},
		},
		{
			name: "With unknown sha256 - got verdict unknown",
			args: args{
				sha256:          unknownSha256,
				expectedVerdict: msg.Unknown,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := new(testFixture)
			vaasClient := fixture.setUp()

			verdict, err := vaasClient.ForSha256(context.Background(), tt.args.sha256)

			if !errors.Is(err, tt.expectedError) {
				t.Fatalf("unexpected error, expected %v but got %v", tt.expectedError, err)
			}

			if err == nil && verdict.Verdict != tt.args.expectedVerdict {
				t.Errorf("verdict should be %v, got %v", tt.args.expectedVerdict, verdict.Verdict)
			}
		})
	}
}
func Test_ForSha256_IfVaasClientException_ReturnClientError(t *testing.T) {
	server := getHttpTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})
	defer server.Close()

	fixture := new(testFixture)
	vaasClient := fixture.setUpWithVaasURL(server.URL)

	_, err := vaasClient.ForSha256(context.Background(), "")
	assert.ErrorIs(t, err, ErrClientFailure)

	// // TODO: verdict.Malicious !!!!
	// assert.Equalf(t, msg.Malicious, verdict.Verdict, "Verdict is not malicious")

}

func Test_ForSha256_SendsUserAgent(t *testing.T) {
	server := getHttpTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, r.Header.Get("User-Agent"), "Go/3.0.10-alpha")
	})
	defer server.Close()

	fixture := new(testFixture)
	vaasClient := fixture.setUpWithVaasURL(server.URL)

	verdict, err := vaasClient.ForSha256(context.Background(), eicarSha256)
	assert.NoError(t, err, "ForSha256 returned err")

	// TODO: verdict.Malicious !!!!
	assert.Equalf(t, msg.Malicious, verdict.Verdict, "Verdict is not malicious")
}

func getHttpTestServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler(w, r)

		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"verdict":"Malicious"}`))
		assert.NoError(t, err)
	}))
}

func TestVaas_ForFile(t *testing.T) {
	const (
		eicarBase64String string = "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo"
	)
	type args struct {
		fileContent     string
		expectedVerdict msg.Verdict
	}
	tests := []struct {
		args          args
		name          string
		expectedError error
	}{
		{
			name: "with eicar file - got verdict malicious",
			args: args{
				fileContent: func() string {
					decodedEicarString, _ := base64.StdEncoding.DecodeString(eicarBase64String)
					return string(decodedEicarString)
				}(),
				expectedVerdict: msg.Malicious,
			},
		},
		{
			name: "With random file - got verdict clean",
			args: args{
				fileContent:     RandomString(200),
				expectedVerdict: msg.Clean,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := new(testFixture)
			vaasClient := fixture.setUp()

			testFile := filepath.Join(t.TempDir(), "testfile")
			if err := os.WriteFile(testFile, []byte(tt.args.fileContent), 0644); err != nil {
				t.Fatalf("error while writing file: %v", err)
			}

			// test disk file
			verdict, err := vaasClient.ForFile(context.Background(), testFile)

			if !errors.Is(err, tt.expectedError) {
				t.Fatalf("unexpected error, expected %v but got %v", tt.expectedError, err)
			}

			if err == nil && verdict.Verdict != tt.args.expectedVerdict {
				t.Errorf("verdict should be %v, got %v", tt.args.expectedVerdict, verdict.Verdict)
			}
		})
	}
}

func TestVaas_ForStream_WithStreamFromString(t *testing.T) {
	eicarReader := strings.NewReader("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
	fixture := new(testFixture)
	vaasClient := fixture.setUp()

	verdict, err := vaasClient.ForStream(context.Background(), eicarReader, eicarReader.Size())

	if err != nil {
		t.Fatalf("unexpected error - %v", err)
	}

	if verdict.Verdict != msg.Malicious {
		t.Errorf("verdict should be %v, got %v", msg.Malicious, verdict.Verdict)
	}
}

func TestVaas_ForStream_WithStreamFromUrl(t *testing.T) {
	response, _ := http.Get("https://secure.eicar.org/eicar.com.txt")

	fixture := new(testFixture)
	vaasClient := fixture.setUp()

	verdict, err := vaasClient.ForStream(context.Background(), response.Body, response.ContentLength)

	if err != nil {
		t.Fatalf("unexpected error - %v", err)
	}

	if verdict.Verdict != msg.Malicious {
		t.Errorf("verdict should be %v, got %v", msg.Malicious, verdict.Verdict)
	}
}

func TestVaas_ForStream_WithDeadlineContext_Cancels(t *testing.T) {
	response, _ := http.Get("https://secure.eicar.org/eicar.com.txt")

	fixture := new(testFixture)
	vaasClient := fixture.setUp()

	cancelCtx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	verdict, err := vaasClient.ForStream(cancelCtx, response.Body, response.ContentLength)

	if err == nil {
		t.Fatalf("expected error got success instead (%v)", verdict)
	}

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected cancelled error, got %v", err)
	}
}

//func TestVaas_ForStream_WithZeroContentLength_ReturnsError(t *testing.T) {
//	response, _ := http.Get("https://secure.eicar.org/eicar.com.txt")
//
//	fixture := new(testFixture)
//	VaasClient := fixture.setUp(t)
//
//	_, err := VaasClient.ForStream(context.Background(), response.Body, 0)
//
//	if err == nil {
//		t.Fatalf("expected error, got nil")
//	}
//
//	if !errors.Is(err, ErrClientFailure) {
//		t.Fatalf("expected error %v, got %v", ErrClientFailure, err)
//	}
//}

func TestVaas_ForStream_WithMaliciousStream_RetunsMaliciousWithDetectionsAndMimeType(t *testing.T) {
	response, _ := http.Get("https://secure.eicar.org/eicar.com.txt")

	fixture := new(testFixture)
	VaasClient := fixture.setUp()

	verdict, err := VaasClient.ForStream(context.Background(), response.Body, response.ContentLength)

	if err != nil {
		t.Fatalf("unexpected error - %v", err)
	}

	if verdict.Verdict != msg.Malicious {
		t.Errorf("verdict should be %v, got %v", msg.Malicious, verdict.Verdict)
	}

	if verdict.MimeType != "text/plain" {
		t.Errorf("expected mime type to be text/plain, got %v", verdict.MimeType)
	}

	if verdict.Detection == "" {
		t.Errorf("expected a detection, got empty string")
	}

	if verdict.Detection != "EICAR-Test-File#462103" {
		t.Errorf("detection has to be EICAR-Test-File#462103, got %v", verdict.Detection)
	}
}

func TestVaas_ForUrl(t *testing.T) {
	const (
		cleanURL   string = "https://www.gdatasoftware.com/oem/verdict-as-a-service"
		eicarURL   string = "https://secure.eicar.org/eicar.com"
		invalidURL string = "https://gateway.production.vaas.gdatasecurity.de/swagger/nocontenthere"
	)
	type args struct {
		url             string
		expectedVerdict msg.Verdict
	}
	tests := []struct {
		args          args
		name          string
		expectedError error
	}{
		{
			name: "with clean url - got verdict clean",
			args: args{
				url:             cleanURL,
				expectedVerdict: msg.Clean,
			},
		},
		{
			name: "with eicar url - got verdict malicious",
			args: args{
				url:             eicarURL,
				expectedVerdict: msg.Malicious,
			},
		},
		{
			name: "with invalid url - got client error",
			args: args{
				url:             invalidURL,
				expectedVerdict: msg.Malicious,
			},
			expectedError: ErrClientFailure,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := new(testFixture)
			VaasClient := fixture.setUp()

			testUrl, err := url.Parse(tt.args.url)
			if err != nil {
				t.Fatalf("Cannot parse test testUrl - %v", err)
			}
			verdict, err := VaasClient.ForUrl(context.Background(), testUrl)

			if !errors.Is(err, tt.expectedError) {
				t.Fatalf("unexpected error, expected %v but got %v", tt.expectedError, err)
			}

			if err == nil && verdict.Verdict != tt.args.expectedVerdict {
				t.Errorf("verdict should be %v, got %v", tt.args.expectedVerdict, verdict.Verdict)
			}
		})
	}
}

func RandomString(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}
