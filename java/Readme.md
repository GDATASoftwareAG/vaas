# gdata-vaas

An SDK to easily utilize G DATA VaaS.

_Verdict-as-a-Service_ (VaaS) is a service that provides a platform for scanning files for malware and other threats. It allows easy integration in your application. With a few lines of code, you can start scanning files for malware.

## What does the SDK do?

It gives you as a developer a functions to talk to G DATA VaaS. It wraps away the complexity of the API into 3 basic functions.

### forSha256

If you calculate the sha256 for a file, you can request that sha256 against G DATA VaaS. It's the fastest way to get a verdict from our service.

### forUrl

If you want to request if a file behind a URL is safe, you can specify the URL as well. Depending on the file size, the duration for the analysis can vary.

### forFile

You can also ask for a file itself. You will still get the benefit of a fast verdict via Sha256 because the SDK will do that for you first. But additionally, if we don't know the file, the file will get uploaded and (automatically) analyzed by us.


## How to use

### Installation

Add this in your ```build.gradle```:
```gradle
implementation 'de.gdata:vaas'
```

### Import

```java
import de.gdata.vaas.ClientCredentialsGrantAuthenticator;
import de.gdata.vaas.Vaas;
import de.gdata.vaas.VaasConfig;
```

### Request a verdict

Authentication & Initializing:
```java
var authenticator = new ClientCredentialsGrantAuthenticator(
    CLIENT_ID,
    CLIENT_SECRET,
    TOKEN_URL
    );
var config = new VaasConfig(
        new URI(TOKEN_URL),
        new URI(VAAS_URL));
var vaas = new Vaas(config, authenticator);
vaas.connect();
```

Verdict Request for SHA256:
```java
var sha256 = new Sha256("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8");
var verdict = vaas.forSha256(sha256);

vaas.disconnect();

System.out.printf("File %s was detected as %s", verdict.getSha256(), verdict.getVerdict());
```

Verdict Request for a file:
```csharp
var file = Path.of(SCAN_PATH);
var verdict = vaas.forFile(file);

vaas.disconnect();

System.out.printf("File %s was detected as %s", verdict.getSha256(), verdict.getVerdict());
```

Verdict Request for a URL:
```java
var url = new URL("https://www.gdatasoftware.com/oem/verdict-as-a-service");
var verdict = vaas.forUrl(url);

vaas.disconnect();

System.out.printf("File %s was detected as %s", verdict.getSha256(), verdict.getVerdict());
```

## <a name="interested"></a>I'm interested in VaaS

You need credentials to use the service in your application. If you are interested in using VaaS, please [contact us](mailto:oem@gdata.de).

## Developing with Visual Studio Code

Every single SDKs also includes [Devcontainer](./devcontainer/). If you use the [Visual Studio Code Dev Containers extension](https://code.visualstudio.com/docs/devcontainers/containers), you can run the code in a full-featured development environment.