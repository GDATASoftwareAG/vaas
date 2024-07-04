// package main implements a simple example of how to
// request a verdict for a file from a VaaS (Verdict as a Service) server using Go.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"

	"github.com/GDATASoftwareAG/vaas/golang/vaas/v2/pkg/authenticator"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/v2/pkg/options"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/v2/pkg/vaas"
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

	// Create a new authenticator with the provided Client ID and Client Secret
	auth := authenticator.NewWithDefaultTokenEndpoint(clientID, clientSecret)

	// Create a new VaaS client with default options
	vaasClient := vaas.NewWithDefaultEndpoint(options.VaasOptions{
		UseHashLookup: true,
		UseCache:      false,
		EnableLogs:    false,
	})

	// Create a context with a cancellation function
	connectCtx, webSocketCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer webSocketCancel()

	// Establish a WebSocket connection to the VaaS server
	termChan, err := vaasClient.Connect(connectCtx, auth)
	if err != nil {
		log.Fatalf("failed to connect to VaaS %s", err.Error())
	}

	// Create a context with a timeout for the analysis
	analysisCtx, analysisCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer analysisCancel()

	// Request a verdict for a specific file (replace "path-to-your-file" with the actual file path)
	result, err := vaasClient.ForFile(analysisCtx, "path-to-your-file")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(result.Verdict)

	// Close the WebSocket connection
	err = vaasClient.Close()
	if err != nil {
		log.Fatalf("failed to close VaaS connection %s", err.Error())
	}

	// Wait for the WebSocket to terminate and handle any errors
	if err = <-termChan; err != nil {
		log.Printf("Websocket shutdown with an error - %v", err)
	}
}
