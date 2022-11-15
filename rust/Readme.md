# gdata-vaas

An SDK to easily utilize G DATA VaaS.

_Verdict-as-a-Service_ (VaaS) is a service that provides a platform for scanning files for malware and other threats. It allows easy integration in your application. With a few lines of code, you can start scanning files for malware.

## What does the SDK do?

It gives you as a developer a functions to talk to G DATA VaaS. It wraps away the complexity of the API into 5 basic functions.

### for_sha256

If you calculate the sha256 for a file, you can request that sha256 against G DATA VaaS. It's the fastest way to get a verdict from our service.

### for_sha256_list

You can also request multiple sha256 with a single function call.

### for_url

If you want to request if a file behind a URL is safe, you can specify the URL as well. Depending on the file size, the duration for the analysis can vary.

### for_file

You can also ask for a file itself. You will still get the benefit of a fast verdict via Sha256 because the SDK will do that for you first. But additionally, if we don't know the file, the file will get uploaded and (automatically) analyzed by us.

### for_file_list

You can also request multiple files with a single function call.

## How to use

### Installation

```bash
cargo add vaas
```

### Import

```rust
use vaas::{message::Verdict, CancellationToken, Connection, Sha256, Vaas};
```

### Request a verdict

Authentication & Initializing:
```rust
let token = Vaas::get_token(&client_id, &client_secret).await?;
let vaas = Vaas::builder(token.into()).build()?.connect().await?;
```

Verdict Request for SHA256:
```rust
let sha256 =
    Sha256::try_from("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8")
        .unwrap();
let ct = CancellationToken::from_seconds(10);        
let verdict = vaas.for_sha256(&sha256, &ct).await;
```

Verdict Request for a file:
```rust
let ct = CancellationToken::from_seconds(10);
let pathToScan = Path::new("/path/to/scan");
let verdict = vaas.for_file(&pathToScan, &ct).await;
```

Verdict Request for a URL:
```rust
let ct = CancellationToken::from_seconds(10);
let url = Url::parse("https://www.gdatasoftware.com/oem/verdict-as-a-service").unwrap();
let verdict = vaas.for_url(url, &ct).await;
```

## <a name="interested"></a>I'm interested in VaaS

You need credentials to use the service in your application. If you are interested in using VaaS, please [contact us](mailto:oem@gdata.de).

## Developing with Visual Studio Code

Every single SDKs also includes [Devcontainer](./devcontainer/). If you use the [Visual Studio Code Dev Containers extension](https://code.visualstudio.com/docs/devcontainers/containers), you can run the code in a full-featured development environment.