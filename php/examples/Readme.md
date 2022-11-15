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

```bash
composer require gdata/vaas
```

### Import

```php
use VaasSdk\ClientCredentialsGrantAuthenticator;
use VaasSdk\Vaas;
```

### Request a verdict

Authentication & Initializing:
```php
$authenticator = new ClientCredentialsGrantAuthenticator(
    $CLIENT_ID,
    $CLIENT_SECRET,
    $TOKEN_URL
);
$vaas = new Vaas($VAAS_URL);
$vaas->Connect($authenticator->getToken());
```

Verdict Request for SHA256:
```php
$vaasVerdict = $vaas->ForSha256("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8");
fwrite(STDOUT, "Verdict for $vaasVerdict->Sha256 is $vaasVerdict->Verdict \n");
```

Verdict Request for a file:
```php
$scanPath = getenv("SCAN_PATH");
$vaasVerdict = $vaas->ForFile($scanPath);
fwrite(STDOUT, "Verdict for $vaasVerdict->Sha256 is $vaasVerdict->Verdict \n");
```

Verdict Request for a URL:
```php
$vaasVerdict = $vaas->ForUrl("https://www.gdatasoftware.com/oem/verdict-as-a-service");
fwrite(STDOUT, "Verdict for $vaasVerdict->Sha256 is $vaasVerdict->Verdict \n");
```

## <a name="interested"></a>I'm interested in VaaS

You need credentials to use the service in your application. If you are interested in using VaaS, please [contact us](mailto:oem@gdata.de).

## Developing with Visual Studio Code

Every single SDKs also includes [Devcontainer](./devcontainer/). If you use the [Visual Studio Code Dev Containers extension](https://code.visualstudio.com/docs/devcontainers/containers), you can run the code in a full-featured development environment.