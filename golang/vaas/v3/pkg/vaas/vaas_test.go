package vaas

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/v3/pkg/authenticator"
	msg "github.com/GDATASoftwareAG/vaas/golang/vaas/v3/pkg/messages"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/v3/pkg/options"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type testFixture struct {
	vaasClient Vaas
	errorChan  <-chan error
}

const (
	eicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
	eicarUrl    = "https://secure.eicar.org/eicar.com"
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
	tokenEndpoint, exists := os.LookupEnv("TOKEN_URL")
	if !exists {
		log.Fatal("no token endpoint configured")
	}

	auth := authenticator.New(clientID, clientSecret, tokenEndpoint)
	tf.setUpWithVaasURLAndAuthenticator(vaasURLString, auth)
	return tf.vaasClient
}

func (tf *testFixture) setUpWithVaasURLAndAuthenticator(vaasURLString string, auth authenticator.Authenticator) Vaas {
	if err := godotenv.Load(); err != nil {
		log.Printf("failed to load environment - %v", err)
	}

	vaasURL, err := url.Parse(vaasURLString)
	if err != nil {
		log.Fatal(err)
	}

	tf.vaasClient = New(vaasURL, auth)

	return tf.vaasClient
}

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

			verdict, err := vaasClient.ForSha256(context.Background(), tt.args.sha256, nil)

			if !errors.Is(err, tt.expectedError) {
				t.Fatalf("unexpected error, expected %v but got %v", tt.expectedError, err)
			}

			if err == nil && verdict.Verdict != tt.args.expectedVerdict {
				t.Errorf("verdict should be %v, got %v", tt.args.expectedVerdict, verdict.Verdict)
			}
		})
	}
}

func Test_ForSha256_IfVaasRequestIdIsSet_SendsTraceState(t *testing.T) {
	server := getHttpTestServer(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, r.Header.Get("tracestate"), "vaasrequestid=MyRequestId")
		defaultHttpHandler(t, w, r)
	})
	defer server.Close()

	fixture := new(testFixture)
	vaasClient := fixture.setUpWithVaasURL(server.URL)

	opts := options.NewForSha256Options()
	opts.VaasRequestId = "MyRequestId"
	_, err := vaasClient.ForSha256(context.Background(), eicarSha256, &opts)
	assert.NoError(t, err, "ForSha256 returned err")
}

func Test_ForSha256_SendsUserAgent(t *testing.T) {
	server := getHttpTestServer(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, r.Header.Get("User-Agent"), "Go/3.0.10-alpha")
		defaultHttpHandler(t, w, r)
	})
	defer server.Close()

	fixture := new(testFixture)
	vaasClient := fixture.setUpWithVaasURL(server.URL)

	verdict, err := vaasClient.ForSha256(context.Background(), eicarSha256, nil)
	assert.NoError(t, err, "ForSha256 returned err")
	assert.Equalf(t, msg.Malicious, verdict.Verdict, "Verdict is not malicious")
}

func Test_ForSha256_SendsOptions(t *testing.T) {
	tests := []options.ForSha256Options{
		{
			UseHashLookup: true,
			UseCache:      true,
		},
		{
			UseHashLookup: true,
			UseCache:      false,
		},
		{
			UseHashLookup: false,
			UseCache:      true,
		},
		{
			UseHashLookup: false,
			UseCache:      false,
		},
	}

	for _, option := range tests {
		t.Run(fmt.Sprintf("%v", option), func(t *testing.T) {
			server := getHttpTestServer(func(w http.ResponseWriter, r *http.Request) {
				useCache := strconv.FormatBool(option.UseCache)
				useHashLookup := strconv.FormatBool(option.UseHashLookup)
				expectedUrl := fmt.Sprintf("/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/report?useCache=%s&useHashLookup=%s", useCache, useHashLookup)
				assert.Equal(t, expectedUrl, r.URL.String())
				defaultHttpHandler(t, w, r)
			})
			defer server.Close()
			fixture := new(testFixture)
			vaasClient := fixture.setUpWithVaasURL(server.URL)

			_, err := vaasClient.ForSha256(context.Background(), eicarSha256, &option)
			assert.NoError(t, err, "ForSha256 returned err")
		})
	}
}

func Test_ForSha256_IfVaasClientException_ReturnErrVaasClient(t *testing.T) {
	server := getHttpTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})
	defer server.Close()
	fixture := new(testFixture)
	vaasClient := fixture.setUpWithVaasURL(server.URL)

	_, err := vaasClient.ForSha256(context.Background(), "", nil)

	assert.ErrorIs(t, err, ErrVaasClient)
}

func Test_ForSha256_IfVaasServerException_ReturnErrVaasServer(t *testing.T) {
	server := getHttpTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer server.Close()
	fixture := new(testFixture)
	vaasClient := fixture.setUpWithVaasURL(server.URL)

	_, err := vaasClient.ForSha256(context.Background(), eicarSha256, nil)

	assert.ErrorIs(t, err, ErrVaasServer)
}

func Test_ForSha256_IfVaasReturns401_ReturnErrVaasAuthentication(t *testing.T) {
	server := getHttpTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	defer server.Close()
	fixture := new(testFixture)
	vaasClient := fixture.setUpWithVaasURL(server.URL)

	_, err := vaasClient.ForSha256(context.Background(), eicarSha256, nil)

	assert.ErrorIs(t, err, ErrVaasAuthentication)
}

func Test_ForSha256_IfAuthenticationFailure_ReturnErrVaasAuthentication(t *testing.T) {
	server := getHttpTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	defer server.Close()
	fixture := new(testFixture)

	vaasClient := fixture.setUpWithVaasURLAndAuthenticator(server.URL, mockFailureAuthenticator{})

	_, err := vaasClient.ForSha256(context.Background(), eicarSha256, nil)

	assert.ErrorIs(t, err, ErrVaasAuthentication)
	assert.ErrorContains(t, err, "placeholder error message")
}

func TestVaas_ForSha256_WithDeadlineContext_Cancels(t *testing.T) {
	fixture := new(testFixture)
	vaasClient := fixture.setUp()

	cancelCtx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	verdict, err := vaasClient.ForSha256(cancelCtx, eicarSha256, nil)

	if err == nil {
		t.Fatalf("expected error got success instead (%v)", verdict)
	}

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected cancelled error, got %v", err)
	}
}

type mockFailureAuthenticator struct {
}

func (m mockFailureAuthenticator) GetToken() (string, error) {
	return "", errors.New("placeholder error message")
}

func getHttpTestServer(handler func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(handler))
}

func defaultHttpHandler(t *testing.T, w http.ResponseWriter, r *http.Request) {
	if r.URL.String() == "/urls" {
		w.WriteHeader(http.StatusCreated)
		_, err := w.Write([]byte(`{"id":"1"}`))
		assert.NoError(t, err)
		return
	}
	if r.URL.String() == "/urls/1/report" {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(fmt.Sprintf(`{"verdict":"Malicious","sha256":"%s","url":"%s"}`, eicarSha256, eicarUrl)))
		assert.NoError(t, err)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte(fmt.Sprintf(`{"verdict":"Malicious","sha256":"%s"}`, eicarSha256)))
	assert.NoError(t, err)
}

func createEicarFile(t *testing.T) string {
	const (
		eicarString string = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
	)
	testFile := filepath.Join(t.TempDir(), "testfile")
	if err := os.WriteFile(testFile, []byte(eicarString), 0644); err != nil {
		t.Fatalf("error while writing file: %v", err)
	}
	return testFile
}

func Test_ForFile(t *testing.T) {
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
			verdict, err := vaasClient.ForFile(context.Background(), testFile, nil)

			if !errors.Is(err, tt.expectedError) {
				t.Fatalf("unexpected error, expected %v but got %v", tt.expectedError, err)
			}

			if err == nil && verdict.Verdict != tt.args.expectedVerdict {
				t.Errorf("verdict should be %v, got %v", tt.args.expectedVerdict, verdict.Verdict)
			}
		})
	}
}

func Test_ForFile_IfVaasRequestIdIsSet_SendsTraceState(t *testing.T) {
	eicar := createEicarFile(t)
	server := getHttpTestServer(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, r.Header.Get("tracestate"), "vaasrequestid=MyRequestId")
		defaultHttpHandler(t, w, r)
	})
	defer server.Close()

	fixture := new(testFixture)
	vaasClient := fixture.setUpWithVaasURL(server.URL)

	opts := options.NewForFileOptions()
	opts.VaasRequestId = "MyRequestId"
	_, err := vaasClient.ForFile(context.Background(), eicar, &opts)
	assert.NoError(t, err)
}

func Test_ForFile_SendsUserAgent(t *testing.T) {
	eicar := createEicarFile(t)
	server := getHttpTestServer(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, r.Header.Get("User-Agent"), "Go/3.0.10-alpha")
		defaultHttpHandler(t, w, r)
	})
	defer server.Close()

	fixture := new(testFixture)
	vaasClient := fixture.setUpWithVaasURL(server.URL)

	verdict, err := vaasClient.ForFile(context.Background(), eicar, nil)
	assert.NoError(t, err, "ForFile returned err")
	assert.Equalf(t, msg.Malicious, verdict.Verdict, "Verdict is not malicious")
}

func Test_ForFile_SendsOptions(t *testing.T) {
	tests := []options.ForFileOptions{
		{
			UseHashLookup: true,
			UseCache:      true,
		},
		{
			UseHashLookup: true,
			UseCache:      false,
		},
		{
			UseHashLookup: false,
			UseCache:      true,
		},
		{
			UseHashLookup: false,
			UseCache:      false,
		},
	}

	eicar := createEicarFile(t)

	for _, option := range tests {
		t.Run(fmt.Sprintf("%v", option), func(t *testing.T) {
			server := getHttpTestServer(func(w http.ResponseWriter, r *http.Request) {
				useCache := strconv.FormatBool(option.UseCache)
				useHashLookup := strconv.FormatBool(option.UseHashLookup)
				expectedUrl := fmt.Sprintf("/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/report?useCache=%s&useHashLookup=%s", useCache, useHashLookup)
				assert.Equal(t, expectedUrl, r.URL.String())
				defaultHttpHandler(t, w, r)
			})
			defer server.Close()
			fixture := new(testFixture)
			vaasClient := fixture.setUpWithVaasURL(server.URL)

			_, err := vaasClient.ForFile(context.Background(), eicar, &option)
			assert.NoError(t, err)
		})
	}
}

func Test_ForFile_IfVaasClientException_ReturnErrVaasClient(t *testing.T) {
	eicar := createEicarFile(t)
	server := getHttpTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})
	defer server.Close()
	fixture := new(testFixture)
	vaasClient := fixture.setUpWithVaasURL(server.URL)

	_, err := vaasClient.ForFile(context.Background(), eicar, nil)

	assert.ErrorIs(t, err, ErrVaasClient)
}

func Test_ForFile_IfVaasServerException_ReturnErrVaasServer(t *testing.T) {
	eicar := createEicarFile(t)
	server := getHttpTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer server.Close()
	fixture := new(testFixture)
	vaasClient := fixture.setUpWithVaasURL(server.URL)

	_, err := vaasClient.ForFile(context.Background(), eicar, nil)

	assert.ErrorIs(t, err, ErrVaasServer)
}

func Test_ForFile_IfVaasReturns401_ReturnErrVaasAuthentication(t *testing.T) {
	eicar := createEicarFile(t)
	server := getHttpTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	defer server.Close()
	fixture := new(testFixture)
	vaasClient := fixture.setUpWithVaasURL(server.URL)

	_, err := vaasClient.ForFile(context.Background(), eicar, nil)

	assert.ErrorIs(t, err, ErrVaasAuthentication)
}

func Test_ForFile_IfAuthenticationFailure_ReturnErrVaasAuthentication(t *testing.T) {
	eicar := createEicarFile(t)
	server := getHttpTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	defer server.Close()
	fixture := new(testFixture)

	vaasClient := fixture.setUpWithVaasURLAndAuthenticator(server.URL, mockFailureAuthenticator{})

	_, err := vaasClient.ForFile(context.Background(), eicar, nil)

	assert.ErrorIs(t, err, ErrVaasAuthentication)
	assert.ErrorContains(t, err, "placeholder error message")
}

func TestVaas_ForFile_WithDeadlineContext_Cancels(t *testing.T) {
	eicar := createEicarFile(t)
	fixture := new(testFixture)
	vaasClient := fixture.setUp()

	cancelCtx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	verdict, err := vaasClient.ForFile(cancelCtx, eicar, nil)

	if err == nil {
		t.Fatalf("expected error got success instead (%v)", verdict)
	}

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected cancelled error, got %v", err)
	}
}

func Test_ForStream_WithEicarString_ReturnsMalicious(t *testing.T) {
	eicarReader := strings.NewReader("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
	fixture := new(testFixture)
	vaasClient := fixture.setUp()

	verdict, err := vaasClient.ForStream(context.Background(), eicarReader, eicarReader.Size(), nil)

	if err != nil {
		t.Fatalf("unexpected error - %v", err)
	}

	if verdict.Verdict != msg.Malicious {
		t.Errorf("verdict should be %v, got %v", msg.Malicious, verdict.Verdict)
	}
}

func Test_ForStream_WitEicarFromUrl_ReturnsMalicious(t *testing.T) {
	response, _ := http.Get("https://secure.eicar.org/eicar.com.txt")

	fixture := new(testFixture)
	vaasClient := fixture.setUp()

	verdict, err := vaasClient.ForStream(context.Background(), response.Body, response.ContentLength, nil)

	if err != nil {
		t.Fatalf("unexpected error - %v", err)
	}

	if verdict.Verdict != msg.Malicious {
		t.Errorf("verdict should be %v, got %v", msg.Malicious, verdict.Verdict)
	}
}

func Test_ForStream_SendsUserAgent(t *testing.T) {
	eicarReader := strings.NewReader("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
	server := getHttpTestServer(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/report") {
			assert.Equal(t, r.Header.Get("User-Agent"), "Go/3.0.10-alpha")
			defaultHttpHandler(t, w, r)
		} else {
			assert.Equal(t, r.Header.Get("User-Agent"), "Go/3.0.10-alpha")
			w.WriteHeader(http.StatusCreated)
			_, err := w.Write([]byte(`{"sha256": "12345"}`))
			assert.NoError(t, err)
		}
	})
	defer server.Close()

	fixture := new(testFixture)
	vaasClient := fixture.setUpWithVaasURL(server.URL)

	verdict, err := vaasClient.ForStream(context.Background(), eicarReader, eicarReader.Size(), nil)
	assert.NoError(t, err, "ForStream returned err")
	assert.Equalf(t, msg.Malicious, verdict.Verdict, "Verdict is not malicious")
}

func Test_ForStream_SendsOptions(t *testing.T) {
	eicarReader := strings.NewReader("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
	tests := []options.ForStreamOptions{
		{
			UseHashLookup: true,
		},
		{
			UseHashLookup: false,
		},
	}

	for _, option := range tests {
		t.Run(fmt.Sprintf("%v", option), func(t *testing.T) {
			server := getHttpTestServer(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/report") {
					defaultHttpHandler(t, w, r)
				} else {
					useHashLookup := strconv.FormatBool(option.UseHashLookup)
					expectedUrl := fmt.Sprintf("/files?useHashLookup=%s", useHashLookup)
					assert.Equal(t, expectedUrl, r.URL.String())
					w.WriteHeader(http.StatusCreated)
					_, err := w.Write([]byte(`{"sha256": "12345"}`))
					assert.NoError(t, err)
				}
			})
			defer server.Close()
			fixture := new(testFixture)
			vaasClient := fixture.setUpWithVaasURL(server.URL)

			_, err := vaasClient.ForStream(context.Background(), eicarReader, eicarReader.Size(), &option)
			assert.NoError(t, err)
		})
	}
}

func Test_ForStream_IfVaasRequestIdIsSet_SendsTraceState(t *testing.T) {
	eicarReader := strings.NewReader("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
	server := getHttpTestServer(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/report") {
			assert.Equal(t, r.Header.Get("tracestate"), "vaasrequestid=MyRequestId")
			defaultHttpHandler(t, w, r)
		} else {
			assert.Equal(t, r.Header.Get("tracestate"), "vaasrequestid=MyRequestId")
			w.WriteHeader(http.StatusCreated)
			_, err := w.Write([]byte(`{"sha256": "12345"}`))
			assert.NoError(t, err)
		}
	})
	defer server.Close()

	fixture := new(testFixture)
	vaasClient := fixture.setUpWithVaasURL(server.URL)

	opts := options.NewForStreamOptions()
	opts.VaasRequestId = "MyRequestId"
	_, err := vaasClient.ForStream(context.Background(), eicarReader, eicarReader.Size(), &opts)
	assert.NoError(t, err)
}

func Test_ForStream_IfVaasClientException_ReturnErrVaasClient(t *testing.T) {
	eicarReader := strings.NewReader("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
	server := getHttpTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})
	defer server.Close()
	fixture := new(testFixture)
	vaasClient := fixture.setUpWithVaasURL(server.URL)

	_, err := vaasClient.ForStream(context.Background(), eicarReader, eicarReader.Size(), nil)

	assert.ErrorIs(t, err, ErrVaasClient)
}

func Test_ForStream_IfVaasServerException_ReturnErrVaasServer(t *testing.T) {
	eicarReader := strings.NewReader("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
	server := getHttpTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer server.Close()
	fixture := new(testFixture)
	vaasClient := fixture.setUpWithVaasURL(server.URL)

	_, err := vaasClient.ForStream(context.Background(), eicarReader, eicarReader.Size(), nil)

	assert.ErrorIs(t, err, ErrVaasServer)
}

func Test_ForStream_IfVaasReturns401_ReturnErrVaasAuthentication(t *testing.T) {
	eicarReader := strings.NewReader("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
	server := getHttpTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	defer server.Close()
	fixture := new(testFixture)
	vaasClient := fixture.setUpWithVaasURL(server.URL)

	_, err := vaasClient.ForStream(context.Background(), eicarReader, eicarReader.Size(), nil)

	assert.ErrorIs(t, err, ErrVaasAuthentication)
}

func Test_ForStream_IfAuthenticationFailure_ReturnErrVaasAuthentication(t *testing.T) {
	eicarReader := strings.NewReader("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
	server := getHttpTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	defer server.Close()
	fixture := new(testFixture)

	vaasClient := fixture.setUpWithVaasURLAndAuthenticator(server.URL, mockFailureAuthenticator{})

	_, err := vaasClient.ForStream(context.Background(), eicarReader, eicarReader.Size(), nil)

	assert.ErrorIs(t, err, ErrVaasAuthentication)
	assert.ErrorContains(t, err, "placeholder error message")
}

func Test_ForStream_WithDeadlineContext_Cancels(t *testing.T) {
	response, _ := http.Get("https://secure.eicar.org/eicar.com.txt")

	fixture := new(testFixture)
	vaasClient := fixture.setUp()

	cancelCtx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	verdict, err := vaasClient.ForStream(cancelCtx, response.Body, response.ContentLength, nil)

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
//	if !errors.Is(err, ErrVaasClient) {
//		t.Fatalf("expected error %v, got %v", ErrVaasClient, err)
//	}
//}

func TestVaas_ForStream_WithMaliciousStream_RetunsMaliciousWithDetectionsAndMimeType(t *testing.T) {
	response, _ := http.Get("https://secure.eicar.org/eicar.com.txt")

	fixture := new(testFixture)
	VaasClient := fixture.setUp()

	verdict, err := VaasClient.ForStream(context.Background(), response.Body, response.ContentLength, nil)

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
			expectedError: ErrVaasClient,
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
			verdict, err := VaasClient.ForUrl(context.Background(), testUrl, nil)

			if !errors.Is(err, tt.expectedError) {
				t.Fatalf("unexpected error, expected %v but got %v", tt.expectedError, err)
			}

			if err == nil && verdict.Verdict != tt.args.expectedVerdict {
				t.Errorf("verdict should be %v, got %v", tt.args.expectedVerdict, verdict.Verdict)
			}
		})
	}
}

func Test_ForUrl_IfVaasRequestIdIsSet_SendsTraceState(t *testing.T) {
	server := getHttpTestServer(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, r.Header.Get("tracestate"), "vaasrequestid=MyRequestId")
		defaultHttpHandler(t, w, r)
	})
	defer server.Close()

	fixture := new(testFixture)
	vaasClient := fixture.setUpWithVaasURL(server.URL)

	opts := options.NewForUrlOptions()
	opts.VaasRequestId = "MyRequestId"
	u, err := url.Parse(eicarUrl)
	_, err = vaasClient.ForUrl(context.Background(), u, &opts)
	assert.NoError(t, err, "ForUrl returned err")
}

func Test_ForUrl_SendsUserAgent(t *testing.T) {
	server := getHttpTestServer(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, r.Header.Get("User-Agent"), "Go/3.0.10-alpha")
		defaultHttpHandler(t, w, r)
	})
	defer server.Close()

	fixture := new(testFixture)
	vaasClient := fixture.setUpWithVaasURL(server.URL)

	u, err := url.Parse(eicarUrl)
	_, err = vaasClient.ForUrl(context.Background(), u, nil)
	assert.NoError(t, err, "ForUrl returned err")
}

func Test_ForUrl_SendsOptions(t *testing.T) {
	tests := []options.ForUrlOptions{
		{
			UseHashLookup: false,
		},
		{
			UseHashLookup: true,
		},
	}

	for _, option := range tests {
		t.Run(fmt.Sprintf("%v", option), func(t *testing.T) {
			server := getHttpTestServer(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.String() == "/urls" {
					analysisRequest := msg.URLAnalysisRequest{
						Url:           eicarUrl,
						UseHashLookup: option.UseHashLookup,
					}
					data, err := io.ReadAll(r.Body)
					assert.NoError(t, err)
					err = json.Unmarshal(data, &analysisRequest)
					assert.Equal(t, option.UseHashLookup, analysisRequest.UseHashLookup)

				}
				defaultHttpHandler(t, w, r)
			})
			defer server.Close()
			fixture := new(testFixture)
			vaasClient := fixture.setUpWithVaasURL(server.URL)

			u, err := url.Parse(eicarUrl)
			_, err = vaasClient.ForUrl(context.Background(), u, &option)
			assert.NoError(t, err, "ForUrl returned err")
		})
	}
}

func Test_ForUrl_IfVaasClientException_ReturnErrVaasClient(t *testing.T) {
	server := getHttpTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})
	defer server.Close()
	fixture := new(testFixture)
	vaasClient := fixture.setUpWithVaasURL(server.URL)

	u, err := url.Parse(eicarUrl)
	_, err = vaasClient.ForUrl(context.Background(), u, nil)

	assert.ErrorIs(t, err, ErrVaasClient)
}

func Test_ForUrl_IfVaasServerException_ReturnErrVaasServer(t *testing.T) {
	server := getHttpTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer server.Close()
	fixture := new(testFixture)
	vaasClient := fixture.setUpWithVaasURL(server.URL)

	u, err := url.Parse(eicarUrl)
	_, err = vaasClient.ForUrl(context.Background(), u, nil)

	assert.ErrorIs(t, err, ErrVaasServer)
}

func Test_ForUrl_IfVaasReturns401_ReturnErrVaasAuthentication(t *testing.T) {
	server := getHttpTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	defer server.Close()
	fixture := new(testFixture)
	vaasClient := fixture.setUpWithVaasURL(server.URL)

	u, err := url.Parse(eicarUrl)
	_, err = vaasClient.ForUrl(context.Background(), u, nil)

	assert.ErrorIs(t, err, ErrVaasAuthentication)
}

func Test_ForUrl_IfAuthenticationFailure_ReturnErrVaasAuthentication(t *testing.T) {
	server := getHttpTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	defer server.Close()
	fixture := new(testFixture)

	vaasClient := fixture.setUpWithVaasURLAndAuthenticator(server.URL, mockFailureAuthenticator{})

	u, err := url.Parse(eicarUrl)
	_, err = vaasClient.ForUrl(context.Background(), u, nil)

	assert.ErrorIs(t, err, ErrVaasAuthentication)
	assert.ErrorContains(t, err, "placeholder error message")
}

func Test_ForUrl_WithDeadlineContext_Cancels(t *testing.T) {
	fixture := new(testFixture)
	vaasClient := fixture.setUp()

	cancelCtx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	u, err := url.Parse(eicarUrl)
	verdict, err := vaasClient.ForUrl(cancelCtx, u, nil)

	if err == nil {
		t.Fatalf("expected error got success instead (%v)", verdict)
	}

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected cancelled error, got %v", err)
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
