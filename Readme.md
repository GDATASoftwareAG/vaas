[![vaas-dotnet-ci](https://github.com/GDATASoftwareAG/vaas/actions/workflows/ci-dotnet.yaml/badge.svg)](https://github.com/GDATASoftwareAG/vaas/actions/workflows/ci-dotnet.yaml)
[![vaas-rust-ci](https://github.com/GDATASoftwareAG/vaas/actions/workflows/ci-rust.yaml/badge.svg)](https://github.com/GDATASoftwareAG/vaas/actions/workflows/ci-rust.yaml)[![vaas-typescript-ci](https://github.com/GDATASoftwareAG/vaas/actions/workflows/ci-typescript.yaml/badge.svg)](https://github.com/GDATASoftwareAG/vaas/actions/workflows/ci-typescript.yaml)
[![vaas-ruby-ci](https://github.com/GDATASoftwareAG/vaas/actions/workflows/ci-ruby.yaml/badge.svg)](https://github.com/GDATASoftwareAG/vaas/actions/workflows/ci-ruby.yaml)
[![vaas-java-ci](https://github.com/GDATASoftwareAG/vaas/actions/workflows/ci-java.yaml/badge.svg)](https://github.com/GDATASoftwareAG/vaas/actions/workflows/ci-java.yaml)
[![vaas-python-ci](https://github.com/GDATASoftwareAG/vaas/actions/workflows/ci-python.yaml/badge.svg)](https://github.com/GDATASoftwareAG/vaas/actions/workflows/ci-python.yaml)
[![vaas-php-ci](https://github.com/GDATASoftwareAG/vaas/actions/workflows/ci-php.yaml/badge.svg)](https://github.com/GDATASoftwareAG/vaas/actions/workflows/ci-php.yaml)
[![vaas-golang-ci](https://github.com/GDATASoftwareAG/vaas/actions/workflows/ci-golang.yaml/badge.svg)](https://github.com/GDATASoftwareAG/vaas/actions/workflows/ci-golang.yaml)

# Verdict-as-a-Service

<img align="right" src="assets/G_DATA_VAAS_Logo_R.png" alt="G DATA VaaS logo" style="width:40%">

*Verdict-as-a-Service* (VaaS) is a cloud service that provides capabilities to scan files for malware and other threats. It allows you to easily integrate malware detection in your application with a few lines of code. You can use VaaS to secure any scenario where a file is exchanged or stored, such as:

- Upload forms with file submissions
- Collaboration software like MS Teams, Nextcloud or Slack
- Backup and distributed file storage like Dropbox or OneDrive

With minimal effort, you can check a file, URL or hashsum for malicious content. No local installation of any anti-malware product is necessary. VaaS works out of the box, by providing detections from the G DATA cloud. Hosting VaaS on your own Kubernetes cluster, is an option as well.

Simple example in Rust. Check below for more programming languages.

```rust
use vaas::{error::VResult, CancellationToken, Vaas, VaasVerdict};
use vaas::auth::authenticators::ClientCredentials;
use std::convert::TryFrom;
use std::time::Duration;

#[tokio::main]
async fn main() -> VResult<()> {
    // Cancel the request after 10 seconds if no response is received
    let ct = CancellationToken::from_seconds(10);

    // Authenticate and create VaaS instance
    let authenticator = ClientCredentials::new(CLIENT_ID, CLIENT_SECRET);
    let vaas = Vaas::builder(authenticator).build()?.connect().await?;

    // Open a file we want to check
    let file = std::path::PathBuf::from("myfile");

    // Ask VaaS for a verdict
    let verdict = vaas.for_file(&file, &ct).await?;

    // Prints "Clean", "Pup" or "Malicious"
    println!("{}", verdict.verdict);
    Ok(())
}
```

## How to get started with VaaS
If you are interested in trying out VaaS, you can sign up on our website to create a free trial account. Visit our registration page and follow the instructions to get started. If you have a business case or specific requirements, please contact us at oem@gdata.de to discuss your needs and explore how VaaS can best fit your organization.

## SDKs
We provide SDKs for various programming languages to make it easy for you to integrate VaaS in your application. You can find the source code, examples, and documentation for each SDK in the corresponding repository. Currently, we support the following languages:

|Language|Source Code|Examples|Documentation|Repository|
|--------|-----------|--------|-------------|----------|
|Rust|[Rust SDK](./rust/)| [Examples](./rust/examples)| [docs.rs](https://docs.rs/vaas/latest/vaas/) | [crates.io](https://crates.io/crates/vaas) | 
|Java|[Java SDK](./java/)|[Examples](./java/examples)| [Readme](https://github.com/GDATASoftwareAG/vaas/blob/main/java/Readme.md) | [maven central](https://mvnrepository.com/artifact/de.gdata/vaas)|
|PHP|[PHP SDK](./php/)|[Examples](./php/examples)||[packagist](https://packagist.org/packages/gdata/vaas)|
|TypeScript|[TypeScript SDK](./typescript/)|[Examples](./typescript/examples)|[Readme](https://github.com/GDATASoftwareAG/vaas/blob/main/typescript/Readme.md)|[npmjs](https://www.npmjs.com/package/gdata-vaas)
|Python|[Python SDK](./python/)|[Examples](./python/examples)|[Readme](https://github.com/GDATASoftwareAG/vaas/blob/main/python/README.md)|[pypi](https://pypi.org/project/gdata-vaas/)|
|.NET|[.NET SDK](./dotnet/)|[Examples](./dotnet/examples)||[nuget.org](https://www.nuget.org/packages/GDataCyberDefense.Vaas)|
|Ruby|[Ruby SDK](./ruby/)|[Examples](./ruby/examples)|[Reamde](https://github.com/GDATASoftwareAG/vaas/blob/main/ruby/README.md)|[rubygems](https://rubygems.org/gems/vaas)|
|Go|[Go SDK](./golang/vaas/)|[Examples](./golang/examples)|[Readme](https://github.com/GDATASoftwareAG/vaas/blob/main/golang/vaas/README.md)|[Github](https://github.com/GDATASoftwareAG/vaas/tree/main/golang/vaas)|

The following table shows the functionality supported by each SDK:

|Functionality|Rust|Java|PHP|TypeScript|.NET|Python|Ruby|Golang
|---|---|---|---|---|---|---|---|---|
|Check SHA256|&#9989;|&#9989;|&#9989;|&#9989;|&#9989;|&#9989;|&#9989;|&#9989;|
|Check SHA256 list|&#9989;|&#9989;|&#10060;|&#9989;|&#9989;|&#10060;|&#10060;|&#9989;|
|Check URL|&#9989;|&#9989;|&#9989;|&#9989;|&#9989;|&#9989;|&#9989;|&#9989;|
|Check file|&#9989;|&#9989;|&#9989;|&#9989;|&#9989;|&#9989;|&#9989;|&#9989;|
|Check file list|&#9989;|&#9989;|&#10060;|&#9989;|&#9989;|&#10060;|&#10060;|&#9989;|
|Custom Guids for tracability on user side|&#10060;|&#10060;|&#9989;|&#10060;|&#10060;|&#9989;|&#10060;|&#10060;|


## Integration Ideas for Malware Detection trough VaaS
You can use VaaS to create various applications that scan for malicious content with a few lines of code. Here are some examples:

Create a command line scanner to find malware: [Example](rust/examples/gscan)
<img src="assets/gscan.gif" alt="GScan command line malware scanner" style="width:100%">

Create a KDE Dolphin plugin to scan for malicious content: [Example](rust/examples/kde_dolphin)
<img src="assets/dolphin_plugin.gif" alt="KDE Dolphin malware scanner plugin" style="width:100%">

Create a WordPress plugin that scans all file uploads for malware: [Example](php/examples/wordpress)
<img src="assets/wordpress.gif" alt="Wordpress plugin malware scanner" style="width:100%">
