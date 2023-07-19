package authenticator

import (
	"log"
	"testing"

	"github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/credentials"

	"github.com/joho/godotenv"
)

func TestClientCredentialsGrantAuthenticator_GetToken(t *testing.T) {
	type fields struct{}
	type args struct {
		clientID      string
		clientSecret  string
		tokenEndpoint string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "With valid credentials - got token",
			args: func() args {
				if err := godotenv.Load(); err != nil {
					log.Printf("failed to load environment - %v", err)
				}

				clientID, clientSecret, _, tokenEndpoint := credentials.ReadCredentials()
				return args{
					clientID:      clientID,
					clientSecret:  clientSecret,
					tokenEndpoint: tokenEndpoint,
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
				_, _, _, tokenEndpoint := credentials.ReadCredentials()
				return args{
					clientID:      "foo",
					clientSecret:  "bar",
					tokenEndpoint: tokenEndpoint,
				}
			}(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authenticator := New(tt.args.clientID, tt.args.clientSecret, tt.args.tokenEndpoint)
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
