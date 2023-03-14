# Go VaaS Client

This is a Golang package that provides a client for the G DATA VaaS API.

_Verdict-as-a-Service_ (VaaS) is a service that provides a platform for scanning files for malware and other threats. It allows easy integration in your application. With a few lines of code, you can start scanning files for malware.

## What does the SDK do?

It gives you as a developer a functions to talk to G DATA VaaS. It wraps away the complexity of the API into 5 basic functions.

### `vaas.New(options VaasOptions, vaasUrl string) Vaas`

Creates a new instance of the Vaas interface with the given options and URL. options is an instance of VaasOptions which allows you to customize how the VaaS client behaves. vaasUrl is the URL of the G DATA VaaS API.

### `vaas.Connect(token string) error`

Connects to the G DATA VaaS API using the given authentication token. token is the authentication token provided by G DATA. If authentication fails, an error will be returned.

### `vaas.Authenticate(token string) error`

Sends an authentication request to the G DATA VaaS API using the given authentication token. If authentication is successful, the session ID will be stored in the vaas object.

### `vaas.ForSha256(sha256 string) (messages.VaasVerdict, error)`

Retrieves the verdict for the given SHA256 hash from the G DATA VaaS API. sha256 is the SHA256 hash of the file. If the request fails, an error will be returned. Otherwise, a messages.VaasVerdict object containing the verdict will be returned.

### `vaas.ForSha256List(sha256List []string) ([]messages.VaasVerdict, error)`

Retrieves the verdict for a list of SHA256 hashes from the G DATA VaaS API. sha256List is a list of SHA256 hashes. If the request fails, an error will be returned. Otherwise, a list of messages.VaasVerdict objects containing the verdicts will be returned.

### `vaas.ForFile(file string) (messages.VaasVerdict, error)`

Retrieves the verdict for the given file from the G DATA VaaS API. file is the path to the file. If the file cannot be opened, an error will be returned. Otherwise, a messages.VaasVerdict object containing the verdict will be returned.

### `vaas.ForUrl(url string) (messages.VaasVerdict, error)`

Retrieves the verdict for the given url from the G DATA VaaS API. url is the path to the file. If the file cannot be opened, an error will be returned. Otherwise, a messages.VaasVerdict object containing the verdict will be returned.

## How to use

### Installation

```go
go get -u github.com/GDATASoftwareAG/vaas/golang/vaas
```

### Import

```go
import (
      "github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/authenticator"
      "github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/vaas"
)
```

### Request a verdict

Authentication & Initializing:
```go
authenticator := authenticator.New(CLIENT_ID, CLIENT_SECRET, TOKEN_ENDPOINT)

var accessToken string
if err := authenticator.GetToken(&accessToken); err != nil {
  log.Fatal(err)
}

vaasClient := vaas.New(options.VaasOptions{
  UseShed:  true,
  UseCache: false,
}, VAAS_URL)

if err := vaasClient.Connect(accessToken); err != nil {
  log.Fatal("Something went wrong", err.Error())
}
```

Verdict Request for SHA256:
```go
result, err := vaasClient.ForSha256(sha256)
if err != nil {
  return err
}
fmt.Println(result.Verdict)
```

Verdict Request for a file:
```go
result, err := vaasClient.ForFile(fileList[0])
if err != nil {
  return err
}
fmt.Println(result.Verdict)
```

Verdict Request for a URL:
```go
result, err := vaasClient.ForUrl(urlList[0])
if err != nil {
  return err
}
fmt.Println(result.Verdict)
```
## <a name="interested"></a>I'm interested in VaaS

You need credentials to use the service in your application. If you are interested in using VaaS, please [contact us](mailto:oem@gdata.de).

## Developing with Visual Studio Code

Every single SDKs also includes [Devcontainer](./devcontainer/). If you use the [Visual Studio Code Dev Containers extension](https://code.visualstudio.com/docs/devcontainers/containers), you can run the code in a full-featured development environment.