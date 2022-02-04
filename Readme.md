# Verdict-as-a-Service

*Verdict-as-a-Service* (VaaS) is a service that provides a platform for scanning files for malware and other threats. It allows easy integration in your application. With a few lines of code, you can start scanning files for malware. 



    ATTENTION: All SDKs are currently prototypes and under heavy construction!


## Integration of Malware Detection

Easily integrate malware detection into **any kind** of application, service or platform.

Create a command line scanner to find malware with a few lines of code: [Example](rust/examples/gscan)
<center>
<img src="demo/gscan.gif" alt="GScan command line malware scanner" style="width:75%">
</center>

Create a KDE Dolphin plugin to scan for malicious content with a few lines of code: [Example](rust/examples/kde_dolphin)
<center>
<img src="demo/dolphin_plugin.gif" alt="KDE Dolphin malware scanner plugin" style="width:75%">
</center>

## I'm interested in VaaS

You need credentials to use the service in your application. If your are interested in using VaaS, please [contact us](mailto:oem@gdata.de).

## SDKs

At the moment SDKs for [Rust](./rust/), [Java](./java/), [Typescript](./typescript/) and [PHP](./php/) are available.

|Functionality|Rust|Java|PHP|TypeScript|
|---|---|---|---|---|
|Check SHA256|&#9989;|&#9989;|&#9989;|&#9989;|
|Check SHA256 list|&#9989;|&#10060;|&#10060;|&#10060;|
|Check file|&#9989;|&#9989;|&#9989;|&#9989;|
|Check file list|&#9989;|&#10060;|&#10060;|&#10060;|

### Documentation

Documentation for the SDKs is available in the corresponding SDK folder.

* [Rust SDK](./rust/), [Examples](./rust/examples)
* [Java SDK](./java/)
* [PHP SDK](./php/), [Examples](./php/examples)
* [TypeScript](./typescript/)

### Planned SDKs

The following SDKs are planned but not yet available: *Swift* and *Perl*. If you need SDKs for other languages, please create an issue or contribute an SDK with a pull request.
