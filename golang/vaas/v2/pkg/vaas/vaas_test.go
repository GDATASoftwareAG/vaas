package vaas

import (
	"context"
	"encoding/base64"
	"errors"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/v2/pkg/authenticator"
	msg "github.com/GDATASoftwareAG/vaas/golang/vaas/v2/pkg/messages"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/v2/pkg/options"
	"github.com/joho/godotenv"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testFixture struct {
	vaasClient Vaas
	errorChan  <-chan error
}

func (tf *testFixture) setUp(t *testing.T) Vaas {
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
	vaasURLString, exists := os.LookupEnv("VAAS_URL")
	if !exists {
		log.Fatal("no vaas endpoint configured")
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

//func TestVaas_TerminateRequestsOnBrokenConnection(t *testing.T) {
//	vc := New(options.VaasOptions{
//		UseHashLookup: true,
//		UseCache:      false,
//	}, "").(*vaas)
//	vc.sessionID = "fake-id"
//
//	wsTerm := new(sync.WaitGroup)
//	wsTerm.Add(1)
//
//	waitJSONWrite := new(sync.WaitGroup)
//	waitJSONWrite.Add(1)
//
//	wsMock := mockWebSocket{
//		readJSONFunc: func(_ any) error {
//			wsTerm.Wait()
//			return &websocket.CloseError{Code: websocket.CloseNormalClosure}
//		},
//		writeJSONFunc: func(_ any) error {
//			waitJSONWrite.Done()
//			return nil
//		},
//	}
//	vc.websocketConnection = wsMock
//
//	termChan := vc.serve()
//
//	waitForRequest := new(sync.WaitGroup)
//	waitForRequest.Add(1)
//
//	go func() {
//		defer waitForRequest.Done()
//		verdict, err := vc.ForSha256(context.Background(), "ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2")
//		if err != nil {
//			t.Errorf("ForSha256 failed - %v", err)
//		}
//
//		if verdict.Verdict != msg.Error {
//			t.Errorf("Unexpected verdict - got: %v, want: %v", verdict, msg.Error)
//		}
//	}()
//
//	// Wait until request is send
//	waitJSONWrite.Wait()
//	// Terminate websocket read
//	wsTerm.Done()
//	// Wait for error response
//	waitForRequest.Wait()
//	_ = vc.Close()
//	<-termChan
//}

func TestVaas_ForSha256(t *testing.T) {
	const (
		cleanSha256     string = "cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e"
		maliciousSha256 string = "ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2"
		unknownSha256   string = "1f72c1111111111111f912e40b7323a0192a300b376186c10f6803dc5efe28df"
	)
	type fields struct {
		testingOptions options.VaasOptions
	}
	type args struct {
		sha256          string
		expectedVerdict msg.Verdict
	}
	tests := []struct {
		args          args
		name          string
		fields        fields
		wantErr       bool
		authenticated bool
	}{
		//{
		//	name: "not authenticated - error (invalid operation)",
		//	args: args{
		//		sha256:          cleanSha256,
		//		expectedVerdict: msg.Clean,
		//	},
		//	fields: fields{
		//		testingOptions: options.VaasOptions{
		//			UseHashLookup: true,
		//			UseCache:      false,
		//			EnableLogs:    true,
		//		}},
		//	wantErr:       true,
		//	authenticated: false,
		//},
		{
			name: "With clean sha256 - got verdict clean",
			args: args{
				sha256:          cleanSha256,
				expectedVerdict: msg.Clean,
			},
			fields: fields{
				testingOptions: options.VaasOptions{
					UseHashLookup: true,
					UseCache:      false,
					EnableLogs:    true,
				}},
			wantErr:       false,
			authenticated: true,
		},
		{
			name: "With malicious sha256 - got verdict malicious",
			args: args{
				sha256:          maliciousSha256,
				expectedVerdict: msg.Malicious,
			},
			fields: fields{
				testingOptions: options.VaasOptions{
					UseHashLookup: true,
					UseCache:      false,
					EnableLogs:    true,
				}},
			wantErr:       false,
			authenticated: true,
		},
		{
			name: "With unknown sha256 - got verdict unknown",
			args: args{
				sha256:          unknownSha256,
				expectedVerdict: msg.Unknown,
			},
			fields: fields{
				testingOptions: options.VaasOptions{
					UseHashLookup: true,
					UseCache:      false,
					EnableLogs:    true,
				}},
			wantErr:       false,
			authenticated: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := new(testFixture)
			vaasClient := fixture.setUp(t)

			verdict, err := vaasClient.ForSha256(context.Background(), tt.args.sha256)

			if (err != nil) != tt.wantErr {
				t.Fatalf("unexpected error - %v", err)
			}

			if err == nil && verdict.Verdict != tt.args.expectedVerdict {
				t.Errorf("verdict should be %v, got %v", tt.args.expectedVerdict, verdict.Verdict)
			}
		})
	}
}

func TestVaas_ForFile(t *testing.T) {
	const (
		eicarBase64String string = "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo"
	)
	type fields struct {
		testingOptions options.VaasOptions
	}
	type args struct {
		fileContent     string
		expectedVerdict msg.Verdict
	}
	tests := []struct {
		args          args
		name          string
		fields        fields
		wantErr       bool
		authenticated bool
	}{
		//{
		//	name: "not authenticated - error (invalid operation)",
		//	args: args{
		//		fileContent: func() string {
		//			decodedEicarString, _ := base64.StdEncoding.DecodeString(eicarBase64String)
		//			return string(decodedEicarString)
		//		}(),
		//		expectedVerdict: msg.Malicious,
		//	},
		//	fields: fields{
		//		testingOptions: options.VaasOptions{
		//			UseHashLookup: true,
		//			UseCache:      false,
		//		}},
		//	wantErr:       true,
		//	authenticated: false,
		//},
		{
			name: "with eicar file - got verdict malicious",
			args: args{
				fileContent: func() string {
					decodedEicarString, _ := base64.StdEncoding.DecodeString(eicarBase64String)
					return string(decodedEicarString)
				}(),
				expectedVerdict: msg.Malicious,
			},
			fields: fields{
				testingOptions: options.VaasOptions{
					UseHashLookup: true,
					UseCache:      false,
				}},
			wantErr:       false,
			authenticated: true,
		},
		{
			name: "With random file - got verdict clean",
			args: args{
				fileContent:     RandomString(200),
				expectedVerdict: msg.Clean,
			},
			fields: fields{
				testingOptions: options.VaasOptions{
					UseHashLookup: true,
					UseCache:      false,
				}},
			wantErr:       false,
			authenticated: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := new(testFixture)
			vaasClient := fixture.setUp(t)

			testFile := filepath.Join(t.TempDir(), "testfile")
			if err := os.WriteFile(testFile, []byte(tt.args.fileContent), 0644); err != nil {
				t.Fatalf("error while writing file: %v", err)
			}

			// test disk file
			verdict, err := vaasClient.ForFile(context.Background(), testFile)
			if (err != nil) != tt.wantErr {
				t.Fatalf("unexpected error - %v", err)
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
	vaasClient := fixture.setUp(t)

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
	vaasClient := fixture.setUp(t)

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
	vaasClient := fixture.setUp(t)

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
	VaasClient := fixture.setUp(t)

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

//func TestVaas_ForUrl(t *testing.T) {
//	const (
//		cleanURL string = "https://www.gdatasoftware.com/oem/verdict-as-a-service"
//		eicarURL string = "https://secure.eicar.org/eicar.com"
//	)
//	type fields struct {
//		testingOptions options.VaasOptions
//	}
//	type args struct {
//		url             string
//		expectedVerdict msg.Verdict
//	}
//	tests := []struct {
//		args          args
//		name          string
//		fields        fields
//		wantErr       bool
//		authenticated bool
//	}{
//		{
//			name: "not authenticated - error (invalid operation)",
//			args: args{
//				url:             cleanURL,
//				expectedVerdict: msg.Clean,
//			},
//			fields: fields{
//				testingOptions: options.VaasOptions{
//					UseHashLookup: true,
//					UseCache:      false,
//				}},
//			wantErr:       true,
//			authenticated: false,
//		},
//		{
//			name: "with clean url - got verdict clean",
//			args: args{
//				url:             cleanURL,
//				expectedVerdict: msg.Clean,
//			},
//			fields: fields{
//				testingOptions: options.VaasOptions{
//					UseHashLookup: true,
//					UseCache:      false,
//				}},
//			wantErr:       false,
//			authenticated: true,
//		},
//		{
//			name: "with eicar url - got verdict malicious",
//			args: args{
//				url:             eicarURL,
//				expectedVerdict: msg.Malicious,
//			},
//			fields: fields{
//				testingOptions: options.VaasOptions{
//					UseHashLookup: true,
//					UseCache:      false,
//				}},
//			wantErr:       false,
//			authenticated: true,
//		},
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			VaasClient := New(tt.fields.testingOptions, "")
//			if tt.authenticated {
//				fixture := new(testFixture)
//				VaasClient = fixture.setUp(t)
//				defer fixture.tearDown(t)
//			}
//
//			verdict, err := VaasClient.ForUrl(context.Background(), tt.args.url)
//
//			if (err != nil) != tt.wantErr {
//				t.Fatalf("unexpected error - %v", err)
//			}
//
//			if err == nil && verdict.Verdict != tt.args.expectedVerdict {
//				t.Errorf("verdict should be %v, got %v", tt.args.expectedVerdict, verdict.Verdict)
//			}
//		})
//	}
//}

func RandomString(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}
