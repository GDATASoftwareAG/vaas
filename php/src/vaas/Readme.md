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
// If you got a username and password from us, you can use the ResourceOwnerPasswordAuthenticator like this

// $authenticator = new ResourceOwnerPasswordGrantAuthenticator(
//     clientId: getenv("CLIENT_ID"),
//     username: getenv("USERNAME"),
//     password: getenv("PASSWORD"),
//     tokenUrl: getenv("TOKEN_URL")
// );
    
// You may use self registration and create a new username and password for the
// `Password` authentication method by yourself like the example above on https://vaas.gdata.de/login

// If you got a client id and client secret from us, you can use the `Client Credentials` authentication method like this

$authenticator = new ClientCredentialsGrantAuthenticator(
    clientId: getenv("CLIENT_ID"),
    clientSecret: getenv("CLIENT_SECRET"),
    tokenUrl: getenv("TOKEN_URL")
);

$vaas = Vaas::builder()
    ->withAuthenticator($authenticator)
    ->build();
```

Verdict Request for SHA256:
```php
$vaasVerdict = $vaas->forSha256Async(Sha256::TryFromString("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8"))->await();
fwrite(STDOUT, "Verdict for $vaasVerdict->sha256 is " . $vaasVerdict->verdict->value . " \n");
```

Verdict Request for a file:
```php
$scanPath = getenv("SCAN_PATH");
$vaasVerdict = $vaas->forFileAsync($scanPath)->await();

fwrite(STDOUT, "Verdict for $vaasVerdict->sha256 is " . $vaasVerdict->verdict->value . " \n");
```

Verdict Request for a URL:
```php
$vaasVerdict = $vaas->forUrlAsync("https://secure.eicar.org/eicar.com")->await();
fwrite(STDOUT, "Verdict for $vaasVerdict->sha256 is " . $vaasVerdict->verdict->value . " \n");
```

## <a name="interested"></a>I'm interested in VaaS

You need credentials to use the service in your application. If you are interested in using VaaS, please [contact us](mailto:oem@gdata.de).
You can create your test credentials at `https://vaas.gdata.de/login` for free.

There is also the option of hosting the VaaS backend yourself. Just take a look here at the [Helm Chart repository](https://github.com/GDATASoftwareAG/vaas-helm).

## Developing with Visual Studio Code

Every single SDKs also includes [Devcontainer](./devcontainer/). If you use the [Visual Studio Code Dev Containers extension](https://code.visualstudio.com/docs/devcontainers/containers), you can run the code in a full-featured development environment.
