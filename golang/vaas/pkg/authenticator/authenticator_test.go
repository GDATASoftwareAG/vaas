package authenticator

import (
	"testing"

	credentials "github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/credentials"

	"github.com/joho/godotenv"
)

func TestClientCredentialsGrantAuthenticator_GetToken(t *testing.T) {
	type fields struct{}
	type args struct {
		clientId      string
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
					t.Fatalf("failed to load environment - %v", err)
				}

				clientId, clientSecret, _, tokenEndpoint := credentials.ReadCredentials()
				return args{
					clientId:      clientId,
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
					t.Fatalf("failed to load environment - %v", err)
				}
				_, _, _, tokenEndpoint := credentials.ReadCredentials()
				return args{
					clientId:      "foo",
					clientSecret:  "bar",
					tokenEndpoint: tokenEndpoint,
				}
			}(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authenticator := New(tt.args.clientId, tt.args.clientSecret, tt.args.tokenEndpoint)
			var accessToken string
			err := authenticator.GetToken(&accessToken)

			if (err != nil) != tt.wantErr {
				t.Fatalf("unexpected error - %v", err)
			}

			if err == nil && accessToken == "" {
				t.Errorf("token should not be empty")
			}
		})
	}
}
