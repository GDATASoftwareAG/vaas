[![vaas-golang-ci](https://github.com/GDATASoftwareAG/vaas/actions/workflows/ci-golang.yaml/badge.svg)](https://github.com/GDATASoftwareAG/vaas/actions/workflows/ci-golang.yaml)
[![Vulnerability Check](https://github.com/GDATASoftwareAG/vaas/actions/workflows/vulncheck-golang.yml/badge.svg)](https://github.com/GDATASoftwareAG/vaas/actions/workflows/vulncheck-golang.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/GDATASoftwareAG/vaas/golang/vaas/.svg)](https://pkg.go.dev/github.com/GDATASoftwareAG/vaas/golang/vaas/)
[![Go Report Card](https://goreportcard.com/badge/github.com/GDATASoftwareAG/vaas/golang/vaas)](https://goreportcard.com/report/github.com/GDATASoftwareAG/vaas/golang/vaas)

# Go VaaS Client

This is a Golang package that provides a client for the G DATA VaaS API.

_Verdict-as-a-Service_ (VaaS) is a service that provides a platform for scanning files for malware and other threats. It allows easy integration into your application. With a few lines of code, you can start scanning files for malware.

# Table of Contents

- [What does the SDK do?](#what-does-the-sdk-do)
- [How to use](#how-to-use)
    - [Installation](#installation)
    - [Import](#import)
    - [Authentication](#authentication)
        - [Client Credentials Grant](#client-credentials-grant)
        - [Resource Owner Password Grant](#resource-owner-password-grant)
    - [Request a verdict](#request-a-verdict)
- [I'm interested in VaaS](#interested)
- [Developing with Visual Studio Code](#developing-with-visual-studio-code)


## What does the SDK do?

It gives you as a developer functions to talk to G DATA VaaS. It wraps away the complexity of the API into basic functions.

### Connect(ctx context.Context, auth authenticator.Authenticator) (errorChan <-chan error, err error)

Connect opens a websocket connection to the VAAS Server. Use Close() to terminate the connection. The errorChan indicates when a connection was closed. In the case of an unexpected close, an error is written to the channel.

### ForSha256(ctx context.Context, sha256 string) (messages.VaasVerdict, error)

Retrieves the verdict for the given SHA256 hash from the G DATA VaaS API. `ctx` is the context for request cancellation, and `sha256` is the SHA256 hash of the file. If the request fails, an error will be returned. Otherwise, a `messages.VaasVerdict` object containing the verdict will be returned.

### ForFile(ctx context.Context, filePath string) (messages.VaasVerdict, error)

Retrieves the verdict for the given file at the specified `filePath` from the G DATA VaaS API. `ctx` is the context for request cancellation. If the file cannot be opened, an error will be returned. Otherwise, a `messages.VaasVerdict` object containing the verdict will be returned.

### ForFileInMemory(ctx context.Context, fileData io.Reader) (messages.VaasVerdict, error)

Retrieves the verdict for file data provided as an `io.Reader` to the G DATA VaaS API. `ctx` is the context for request cancellation. If the request fails, an error will be returned. Otherwise, a `messages.VaasVerdict` object containing the verdict will be returned.

### ForUrl(ctx context.Context, url string) (messages.VaasVerdict, error)

Retrieves the verdict for the given file URL from the G DATA VaaS API. `ctx` is the context for request cancellation. If the request fails, an error will be returned. Otherwise, a `messages.VaasVerdict` object containing the verdict will be returned.

## How to use

### Installation

```sh
go get github.com/GDATASoftwareAG/vaas/golang/vaas
```

### Import

```go
import (
      "github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/authenticator"
      "github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/vaas"
)
```

### Authentication

VaaS offers two authentication methods:

#### Client Credentials Grant
This is suitable for cases where you have a `client_id`and `client_secret`. Here's how to use it:

```go
authenticator := authenticator.New("client_id", "client_secret", "token_endpoint")
```
or
```go
authenticator := authenticator.NewWithDefaultTokenEndpoint("client_id", "client_secret")
```
#### Resource Owner Password Grant 
This method is used when you have a `username` and `password`. Here's how to use it:

```go
authenticator := authenticator.NewWithResourceOwnerPassword("client_id", "username", "password", "token_endpoint")
```
If you do not have a specific Client ID, please use `"vaas-customer"` as the client_id.

### Request a verdict

Authentication & Initialization:
```go
// Create a new authenticator with the provided Client ID and Client Secret
auth := authenticator.NewWithDefaultTokenEndpoint(clientID, clientSecret)

// Create a new VaaS client with default options
vaasClient := vaas.NewWithDefaultEndpoint(options.VaasOptions{
      UseHashLookup: true,
      UseCache:      false,
      EnableLogs:    false,
})

// Create a context with a cancellation function
ctx, webSocketCancel := context.WithCancel(context.Background())

// Establish a WebSocket connection to the VaaS server
errorChan, err := vaasClient.Connect(ctx, auth)
if err != nil {
      log.Fatalf("failed to connect to VaaS %s", err.Error())
}
defer vaasClient.Close()

// Create a context with a timeout for the analysis
analysisCtx, analysisCancel := context.WithTimeout(context.Background(), 20*time.Second)
defer analysisCancel()
```

Verdict Request for SHA256:
```go
// Request a verdict for a specific SHA256 hash (replace "sha256-hash" with the actual SHA256 hash)
result, err := vaasClient.ForFile(analysisCtx, "sha256-hash")
if err != nil {
    log.Fatalf("Failed to get verdict: %v", err)
}
fmt.Println(result.Verdict)
```

Verdict Request for a file:
```go
// Request a verdict for a specific file (replace "path-to-your-file" with the actual file path)
result, err := vaasClient.ForFile(analysisCtx, "path-to-your-file")
if err != nil {
    log.Fatalf("Failed to get verdict: %v", err)
}
fmt.Printf("Verdict: %s\n", result.Verdict)
```

Verdict Request for file data provided as an io.Reader:
```go
fileData := bytes.NewReader([]byte("file contents"))
result, err := vaasClient.ForFileInMemory(analysisCtx, fileData)
if err != nil {
    log.Fatalf("Failed to get verdict: %v", err)
}
fmt.Printf("Verdict: %s\n", result.Verdict)
```

Verdict Request for a file URL:
```go
result, err := vaasClient.ForUrl(analysisCtx, "https://example.com/examplefile")
if err != nil {
    log.Fatalf("Failed to get verdict: %v", err)
}
fmt.Printf("Verdict: %s\n", result.Verdict)
```


## <a name="interested"></a>I'm interested in VaaS

You need credentials to use the service in your application. If you are interested in using VaaS, please [contact us](mailto:oem@gdata.de).

## Developing with Visual Studio Code

Every single SDKs also includes [Devcontainer](./.devcontainer/). If you use the [Visual Studio Code Dev Containers extension](https://code.visualstudio.com/docs/devcontainers/containers), you can run the code in a full-featured development environment.
