package authenticator

import (
	"log"
	"os"
	"testing"

	"github.com/joho/godotenv"
)

func Test_clientCredentialsGrantAuthenticator_GetToken(t *testing.T) {
	type args struct {
		clientID     string
		clientSecret string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "With valid credentials - got token",
			args: func() args {
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

				return args{
					clientID:     clientID,
					clientSecret: clientSecret,
				}
			}(),
			wantErr: false,
		},
		{
			name: "With invalid credentials - error",
			args: func() args {
				if err := godotenv.Load(); err != nil {
					log.Printf("failed to load environment - %v", err)
				}

				return args{
					clientID:     "foo",
					clientSecret: "bar",
				}
			}(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenEndpoint, exists := os.LookupEnv("TOKEN_URL")
			if !exists {
				log.Fatal("no token endpoint configured")
			}

			authenticator := New(tt.args.clientID, tt.args.clientSecret, tokenEndpoint)
			accessToken, err := authenticator.GetToken()

			if (err != nil) != tt.wantErr {
				t.Fatalf("unexpected error - %v", err)
			}

			if err == nil && accessToken == "" {
				t.Errorf("token should not be empty")
			}
		})
	}
}

func Test_resourceOwnerPasswordGrantAuthenticator_GetToken(t *testing.T) {
	type args struct {
		clientID string
		username string
		password string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "With valid credentials - got token",
			args: func() args {
				if err := godotenv.Load(); err != nil {
					log.Printf("failed to load environment - %v", err)
				}

				clientID, exists := os.LookupEnv("VAAS_CLIENT_ID")
				if !exists {
					log.Fatal("no client-id set")
				}
				username, exists := os.LookupEnv("VAAS_USER_NAME")
				if !exists {
					log.Fatal("no username set")
				}
				password, exists := os.LookupEnv("VAAS_PASSWORD")
				if !exists {
					log.Fatal("no password set")
				}

				return args{
					clientID: clientID,
					username: username,
					password: password,
				}
			}(),
			wantErr: false,
		},
		{
			name: "With invalid credentials - error",
			args: func() args {
				if err := godotenv.Load(); err != nil {
					log.Printf("failed to load environment - %v", err)
				}

				return args{
					clientID: "foo",
					username: "bar",
					password: "baz",
				}
			}(),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenEndpoint, exists := os.LookupEnv("TOKEN_URL")
			if !exists {
				log.Fatal("no token endpoint configured")
			}

			authenticator := NewWithResourceOwnerPassword(tt.args.clientID, tt.args.username, tt.args.password, tokenEndpoint)
			accessToken, err := authenticator.GetToken()

			if (err != nil) != tt.wantErr {
				t.Fatalf("unexpected error - %v", err)
			}

			if err == nil && accessToken == "" {
				t.Errorf("token should not be empty")
			}
		})
	}
}
