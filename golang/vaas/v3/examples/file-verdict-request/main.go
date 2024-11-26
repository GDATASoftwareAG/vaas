// package main implements a simple example of how to
// request a verdict for a file from a VaaS (Verdict as a Service) server using Go.
package main

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"os"
	"time"

	"github.com/joho/godotenv"

	"github.com/GDATASoftwareAG/vaas/golang/vaas/v3/pkg/authenticator"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/v3/pkg/options"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/v3/pkg/vaas"
)

func main() {
	// Load environment variables from a .env file (if it exists)
	if err := godotenv.Load(); err != nil {
		log.Printf("failed to load environment - %v", err)
	}

	// Retrieve the Client ID and Client Secret from environment variables
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
		tokenEndpoint = "https://account-staging.gdata.de/realms/vaas-staging/protocol/openid-connect/token"
	}
	vaasURLString, exists := os.LookupEnv("VAAS_URL")
	if !exists {
		vaasURLString = "https://gateway.staging.vaas.gdatasecurity.de"
	}
	vaasURL, err := url.Parse(vaasURLString)
	if err != nil {
		log.Fatal("VAAS_URL is not an URL")
	}

	scanPath, exists := os.LookupEnv("SCAN_PATH")
	if !exists {
		scanPath = "README.md"
	}

	// Create a new authenticator with the provided Client ID and Client Secret
	auth := authenticator.New(clientID, clientSecret, tokenEndpoint)

	// Create a new VaaS client with default options
	vaasClient := vaas.New(options.VaasOptions{
		UseHashLookup: true,
		UseCache:      false,
	}, vaasURL, auth)

	// Create a context with a timeout for the analysis
	analysisCtx, analysisCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer analysisCancel()

	// Request a verdict for a specific file
	result, err := vaasClient.ForFile(analysisCtx, scanPath)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(result.Verdict)
}
