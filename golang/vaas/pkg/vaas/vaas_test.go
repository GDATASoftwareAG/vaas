package vaas

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"

	"github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/authenticator"
	credentials "github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/credentials"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/messages"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/options"
)

type testFixture struct {
	cancel   context.CancelFunc
	termChan <-chan error
}

func (tf *testFixture) setUp(t *testing.T) Vaas {
	if err := godotenv.Load(); err != nil {
		log.Printf("failed to load environment - %v", err)
	}

	clientID, clientSecret, vaasURL, tokenEndpoint := credentials.ReadCredentials()

	testingOptions := options.VaasOptions{
		UseHashLookup: true,
		UseCache:      false,
	}
	vaasClient := New(testingOptions, vaasURL)

	var ctx context.Context
	ctx, tf.cancel = context.WithCancel(context.Background())

	auth := authenticator.New(clientID, clientSecret, tokenEndpoint)

	termChan, err := vaasClient.Connect(ctx, auth)
	if err != nil {
		t.Fatalf("Failed to connect - %v", err)
	}
	tf.termChan = termChan

	return vaasClient
}

func (tf *testFixture) tearDown(t *testing.T) {
	tf.cancel()
	if err := <-tf.termChan; err != nil {
		t.Errorf("Error during close of websocket - %v", err)
	}
}

func TestVaas_ForSha256(t *testing.T) {
	const (
		cleanSha256     string = "3A78F382E8E2968EC201B33178102E06DB72E4F2D1505E058A4613C1E977825C"
		maliciousSha256 string = "00000b68934493af2f5954593fe8127b9dda6d4b520e78265aa5875623b58c9c"
		unknownSha256   string = "110005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe9"
	)
	type fields struct {
		testingOptions options.VaasOptions
	}
	type args struct {
		sha256          string
		expectedVerdict messages.Verdict
	}
	tests := []struct {
		args          args
		name          string
		fields        fields
		wantErr       bool
		authenticated bool
	}{
		{
			name: "not authenticated - error (invalid operation)",
			args: args{
				sha256:          cleanSha256,
				expectedVerdict: messages.Clean,
			},
			fields: fields{
				testingOptions: options.VaasOptions{
					UseHashLookup: true,
					UseCache:      false,
					EnableLogs:    true,
				}},
			wantErr:       true,
			authenticated: false,
		},
		{
			name: "With clean sha256 - got verdict clean",
			args: args{
				sha256:          cleanSha256,
				expectedVerdict: messages.Clean,
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
				expectedVerdict: messages.Malicious,
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
				expectedVerdict: messages.Unknown,
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
			VaasClient := New(tt.fields.testingOptions, "")
			if tt.authenticated {
				fixture := new(testFixture)
				VaasClient = fixture.setUp(t)
				defer fixture.tearDown(t)
			}

			verdict, err := VaasClient.ForSha256(context.Background(), tt.args.sha256)

			if (err != nil) != tt.wantErr {
				t.Fatalf("unexpected error - %v", err)
			}

			if err == nil && verdict.Verdict != tt.args.expectedVerdict {
				t.Errorf("verdict should be %v, got %v", tt.args.expectedVerdict, verdict.Verdict)
			}
		})
	}
}

func TestVaas_ForFile_And_ForFileInMemory(t *testing.T) {
	const (
		eicarBase64String string = "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo"
	)
	type fields struct {
		testingOptions options.VaasOptions
	}
	type args struct {
		fileContent     string
		expectedVerdict messages.Verdict
	}
	tests := []struct {
		args          args
		name          string
		fields        fields
		wantErr       bool
		authenticated bool
	}{
		{
			name: "not authenticated - error (invalid operation)",
			args: args{
				fileContent: func() string {
					decodedEicarString, _ := base64.StdEncoding.DecodeString(eicarBase64String)
					return string(decodedEicarString)
				}(),
				expectedVerdict: messages.Malicious,
			},
			fields: fields{
				testingOptions: options.VaasOptions{
					UseHashLookup: true,
					UseCache:      false,
				}},
			wantErr:       true,
			authenticated: false,
		},
		{
			name: "with eicar file - got verdict malicious",
			args: args{
				fileContent: func() string {
					decodedEicarString, _ := base64.StdEncoding.DecodeString(eicarBase64String)
					return string(decodedEicarString)
				}(),
				expectedVerdict: messages.Malicious,
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
				expectedVerdict: messages.Clean,
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
			VaasClient := New(tt.fields.testingOptions, "")
			if tt.authenticated {
				fixture := new(testFixture)
				VaasClient = fixture.setUp(t)
				defer fixture.tearDown(t)
			}

			testFile := filepath.Join(t.TempDir(), "testfile")
			if err := os.WriteFile(testFile, []byte(tt.args.fileContent), 0644); err != nil {
				t.Fatalf("error while writing file: %v", err)
			}

			// test disk file
			verdict, err := VaasClient.ForFile(context.Background(), testFile)
			if (err != nil) != tt.wantErr {
				t.Fatalf("unexpected error - %v", err)
			}

			if err == nil && verdict.Verdict != tt.args.expectedVerdict {
				t.Errorf("verdict should be %v, got %v", tt.args.expectedVerdict, verdict.Verdict)
			}

			// test in-memory file
			buf := new(bytes.Buffer)
			_, _ = io.Copy(buf, strings.NewReader(tt.args.fileContent))

			verdict, err = VaasClient.ForFileInMemory(context.Background(), buf)
			if (err != nil) != tt.wantErr {
				t.Fatalf("unexpected error - %v", err)
			}

			if err == nil && verdict.Verdict != tt.args.expectedVerdict {
				t.Errorf("verdict should be %v, got %v", tt.args.expectedVerdict, verdict.Verdict)
			}
		})
	}
}

func TestVaas_ForUrl(t *testing.T) {
	const (
		cleanURL string = "https://random-data-api.com/api/v2/beers"
		eicarURL string = "https://secure.eicar.org/eicar.com"
	)
	type fields struct {
		testingOptions options.VaasOptions
	}
	type args struct {
		url             string
		expectedVerdict messages.Verdict
	}
	tests := []struct {
		args          args
		name          string
		fields        fields
		wantErr       bool
		authenticated bool
	}{
		{
			name: "not authenticated - error (invalid operation)",
			args: args{
				url:             cleanURL,
				expectedVerdict: messages.Clean,
			},
			fields: fields{
				testingOptions: options.VaasOptions{
					UseHashLookup: true,
					UseCache:      false,
				}},
			wantErr:       true,
			authenticated: false,
		},
		{
			name: "with clean url - got verdict clean",
			args: args{
				url:             cleanURL,
				expectedVerdict: messages.Clean,
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
			name: "with eicar url - got verdict malicious",
			args: args{
				url:             eicarURL,
				expectedVerdict: messages.Malicious,
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
			VaasClient := New(tt.fields.testingOptions, "")
			if tt.authenticated {
				fixture := new(testFixture)
				VaasClient = fixture.setUp(t)
				defer fixture.tearDown(t)
			}

			verdict, err := VaasClient.ForUrl(context.Background(), tt.args.url)

			if (err != nil) != tt.wantErr {
				t.Fatalf("unexpected error - %v", err)
			}

			if err == nil && verdict.Verdict != tt.args.expectedVerdict {
				t.Errorf("verdict should be %v, got %v", tt.args.expectedVerdict, verdict.Verdict)
			}
		})
	}
}

func TestVaas_ForSha256List(t *testing.T) {
	fixture := new(testFixture)
	vaasClient := fixture.setUp(t)
	defer fixture.tearDown(t)

	maliciousSha256 := "00000b68934493af2f5954593fe8127b9dda6d4b520e78265aa5875623b58c9c"
	cleanSha256 := "3A78F382E8E2968EC201B33178102E06DB72E4F2D1505E058A4613C1E977825C"
	unknownSha256 := "110005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe9"

	verdicts, err := vaasClient.ForSha256List(context.Background(), []string{maliciousSha256, cleanSha256, unknownSha256})
	if err != nil {
		log.Fatal(err)
	}

	maliciousIndex := Index(verdicts, maliciousSha256)
	unknownIndex := Index(verdicts, unknownSha256)
	cleanIndex := Index(verdicts, cleanSha256)

	assert.Equal(t, messages.Malicious, verdicts[maliciousIndex].Verdict)
	assert.Equal(t, messages.Clean, verdicts[cleanIndex].Verdict)
	assert.Equal(t, messages.Unknown, verdicts[unknownIndex].Verdict)
}

func TestVaas_ForFileList(t *testing.T) {
	fixture := new(testFixture)
	vaasClient := fixture.setUp(t)
	defer fixture.tearDown(t)

	tmpDir := t.TempDir()

	var randomFiles []string
	for i := 0; i < 3; i++ {
		filename := filepath.Join(tmpDir, fmt.Sprintf("cleanFile%d", i))
		if err := os.WriteFile(filename, []byte(RandomString(200)), 0644); err != nil {
			t.Fatalf("error while writing clean file: %v", err)
		}
		randomFiles = append(randomFiles, filename)
	}

	verdicts, err := vaasClient.ForFileList(context.Background(), randomFiles)
	if err != nil {
		log.Fatal(err)
	}

	for _, verdict := range verdicts {
		assert.Equal(t, messages.Clean, verdict.Verdict, verdict.ErrMsg)
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

func Index(s []messages.VaasVerdict, str string) int {
	for i, v := range s {
		if v.Sha256 == str {
			return i
		}
	}

	return -1
}
