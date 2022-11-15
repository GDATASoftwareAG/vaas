# gdata-vaas

An SDK to easily utilize G DATA VaaS.

_Verdict-as-a-Service_ (VaaS) is a service that provides a platform for scanning files for malware and other threats. It allows easy integration in your application. With a few lines of code, you can start scanning files for malware.

## What does the SDK do?

It gives you as a developer a functions to talk to G DATA VaaS. It wraps away the complexity of the API into 5 basic functions.

### forSha256Async

If you calculate the sha256 for a file, you can request that sha256 against G DATA VaaS. It's the fastest way to get a verdict from our service.

### forSha256ListAsync

You can also request multiple sha256 with a single function call.

### forUrlAsync

If you want to request if a file behind a URL is safe, you can specify the URL as well. Depending on the file size, the duration for the analysis can vary.

### forFileAsync

You can also ask for a file itself. You will still get the benefit of a fast verdict via Sha256 because the SDK will do that for you first. But additionally, if we don't know the file, the file will get uploaded and (automatically) analyzed by us.

### forFileListAsync

You can also request multiple files with a single function call.

## How to use

### Installation

```bash
dotnet add package GDataCyberDefense.Vaas
```

### Import

```csharp
using Vaas;
```

### Request a verdict

Authentication & Initializing:
```csharp
var vaas = new Vaas.Vaas();
var authenticator = new ClientCredentialsGrantAuthenticator(
    CLIENT_ID,
    CLIENT_SECRET,
    TOKEN_URL
);
await vaas.Connect(await authenticator.GetToken());
```

Verdict Request for SHA256:
```csharp
var sha256 = "000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8";
var verdict = await vaas.ForSha256Async(sha256);

Console.WriteLine($"{verdict.Sha256} is detected as {verdict.Verdict}");
```

Verdict Request for a file:
```csharp
var file = "/path/to/file";
var verdict = await vaas.ForFileAsync(file);

Console.WriteLine($"{verdict.Sha256} is detected as {verdict.Verdict}");
```

Verdict Request for a URL:
```csharp
var url = "https://www.gdatasoftware.com/oem/verdict-as-a-service";
var verdict = await vaas.ForUrlAsync(new Uri(url));;

Console.WriteLine($"{verdict.Sha256} is detected as {verdict.Verdict}");
```

## I'm interested in VaaS

You need credentials to use the service in your application. If you are interested in using VaaS, please [contact us](mailto:oem@gdata.de).

## Developing with Visual Studio Code

Every single SDKs also includes [Devcontainer](./devcontainer/). If you use the [Visual Studio Code Dev Containers extension](https://code.visualstudio.com/docs/devcontainers/containers), you can run the code in a full-featured development environment.