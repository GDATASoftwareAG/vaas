package vaas

import (
	"encoding/base64"
	"fmt"
	"log"
	"math/rand"
	"os"
	"testing"

	"github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/authenticator"
	credentials "github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/credentials"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/messages"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/options"

	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
)

func setUp() Vaas {
	if err := godotenv.Load(); err != nil {
		log.Printf("failed to load environment - %v", err)
	}

	CLIENT_ID, CLIENT_SECRET, VAAS_URL, TOKEN_ENDPOINT := credentials.ReadCredentials()
	authenticator := authenticator.New(CLIENT_ID, CLIENT_SECRET, TOKEN_ENDPOINT)

	var accessToken string
	if err := authenticator.GetToken(&accessToken); err != nil {
		log.Fatal(err)
	}

	testingOptions := options.VaasOptions{
		UseShed:  true,
		UseCache: false,
	}
	vaasClient := New(testingOptions, VAAS_URL)

	err := vaasClient.Connect(accessToken)
	if err != nil {
		log.Fatal(err)
	}

	return vaasClient
}

func TestVaas_ForSha256(t *testing.T) {
	const (
		cleanSha256     string = "698cda840a0b3d4639f0c5dbd5c629a847a27448a9a179cb6b7a648bc1186f23"
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
		name          string
		fields        fields
		args          args
		wantErr       bool
		authenticated bool
	}{
		{
			name: "not authenticated - error (invalid operation)",
			args: args{
				sha256:          cleanSha256,
				expectedVerdict: messages.Verdict(messages.Clean),
			},
			fields: fields{
				testingOptions: options.VaasOptions{
					UseShed:  true,
					UseCache: false,
				}},
			wantErr:       true,
			authenticated: false,
		},
		{
			name: "With clean sha256 - got verdict clean",
			args: args{
				sha256:          cleanSha256,
				expectedVerdict: messages.Verdict(messages.Clean),
			},
			fields: fields{
				testingOptions: options.VaasOptions{
					UseShed:  true,
					UseCache: false,
				}},
			wantErr:       false,
			authenticated: true,
		},
		{
			name: "With malicious sha256 - got verdict malicious",
			args: args{
				sha256:          maliciousSha256,
				expectedVerdict: messages.Verdict(messages.Malicious),
			},
			fields: fields{
				testingOptions: options.VaasOptions{
					UseShed:  true,
					UseCache: false,
				}},
			wantErr:       false,
			authenticated: true,
		},
		{
			name: "With unknown sha256 - got verdict unknown",
			args: args{
				sha256:          unknownSha256,
				expectedVerdict: messages.Verdict(messages.Unknown),
			},
			fields: fields{
				testingOptions: options.VaasOptions{
					UseShed:  true,
					UseCache: false,
				}},
			wantErr:       false,
			authenticated: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var VaasClient Vaas
			if tt.authenticated {
				VaasClient = setUp()
			} else {
				VaasClient = New(tt.fields.testingOptions, "")
			}

			verdict, err := VaasClient.ForSha256(tt.args.sha256)

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
		expectedVerdict messages.Verdict
	}
	tests := []struct {
		name          string
		fields        fields
		args          args
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
				expectedVerdict: messages.Verdict(messages.Malicious),
			},
			fields: fields{
				testingOptions: options.VaasOptions{
					UseShed:  true,
					UseCache: false,
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
				expectedVerdict: messages.Verdict(messages.Malicious),
			},
			fields: fields{
				testingOptions: options.VaasOptions{
					UseShed:  true,
					UseCache: false,
				}},
			wantErr:       false,
			authenticated: true,
		},
		{
			name: "With random file - got verdict clean",
			args: args{
				fileContent:     RandomString(200),
				expectedVerdict: messages.Verdict(messages.Clean),
			},
			fields: fields{
				testingOptions: options.VaasOptions{
					UseShed:  true,
					UseCache: false,
				}},
			wantErr:       false,
			authenticated: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const testFile string = "testfile"
			var VaasClient Vaas
			if tt.authenticated {
				VaasClient = setUp()
			} else {
				VaasClient = New(tt.fields.testingOptions, "")
			}
			err := os.WriteFile(testFile, []byte(tt.args.fileContent), 0644)
			if err != nil {
				t.Fatalf("error while writing file: %v", err)
			}

			verdict, err := VaasClient.ForFile(testFile)
			os.Remove(testFile)
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
		cleanUrl string = "https://random-data-api.com/api/v2/beers"
		eicarUrl string = "https://secure.eicar.org/eicar.com"
	)
	type fields struct {
		testingOptions options.VaasOptions
	}
	type args struct {
		url             string
		expectedVerdict messages.Verdict
	}
	tests := []struct {
		name          string
		fields        fields
		args          args
		wantErr       bool
		authenticated bool
	}{
		{
			name: "not authenticated - error (invalid operation)",
			args: args{
				url:             cleanUrl,
				expectedVerdict: messages.Verdict(messages.Clean),
			},
			fields: fields{
				testingOptions: options.VaasOptions{
					UseShed:  true,
					UseCache: false,
				}},
			wantErr:       true,
			authenticated: false,
		},
		{
			name: "with clean url - got verdict clean",
			args: args{
				url:             cleanUrl,
				expectedVerdict: messages.Verdict(messages.Clean),
			},
			fields: fields{
				testingOptions: options.VaasOptions{
					UseShed:  true,
					UseCache: false,
				}},
			wantErr:       false,
			authenticated: true,
		},
		{
			name: "with eicar url - got verdict malicious",
			args: args{
				url:             eicarUrl,
				expectedVerdict: messages.Verdict(messages.Malicious),
			},
			fields: fields{
				testingOptions: options.VaasOptions{
					UseShed:  true,
					UseCache: false,
				}},
			wantErr:       false,
			authenticated: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var VaasClient Vaas
			if tt.authenticated {
				VaasClient = setUp()
			} else {
				VaasClient = New(tt.fields.testingOptions, "")
			}

			verdict, err := VaasClient.ForUrl(tt.args.url)

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
	vaasClient := setUp()
	maliciousSha256 := "00000b68934493af2f5954593fe8127b9dda6d4b520e78265aa5875623b58c9c"
	cleanSha256 := "698cda840a0b3d4639f0c5dbd5c629a847a27448a9a179cb6b7a648bc1186f23"
	unknownSha256 := "110005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe9"

	verdicts, err := vaasClient.ForSha256List([]string{maliciousSha256, cleanSha256, unknownSha256})
	if err != nil {
		log.Fatal(err)
	}

	maliciousIndex := Index(verdicts, maliciousSha256)
	unknownIndex := Index(verdicts, unknownSha256)
	cleanIndex := Index(verdicts, cleanSha256)

	assert.Equal(t, verdicts[maliciousIndex].Verdict, messages.Verdict(messages.Malicious))
	assert.Equal(t, verdicts[cleanIndex].Verdict, messages.Verdict(messages.Clean))
	assert.Equal(t, verdicts[unknownIndex].Verdict, messages.Verdict(messages.Unknown))
}

func TestVaas_ForFileList(t *testing.T) {
	vaasClient := setUp()
	var randomFiles []string
	for i := 0; i < 3; i++ {
		filename := "cleanFile" + fmt.Sprint(i)
		err := os.WriteFile(filename, []byte(RandomString(200)), 0644)
		if err != nil {
			t.Fatalf("error while writing clean file: %v", err)
		}
		randomFiles = append(randomFiles, filename)
	}

	verdicts, err := vaasClient.ForFileList(randomFiles)
	if err != nil {
		log.Fatal(err)
	}

	for _, verdict := range verdicts {
		assert.Equal(t, verdict.Verdict, messages.Verdict(messages.Clean))
	}

	for _, file := range randomFiles {
		os.Remove(file)
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
