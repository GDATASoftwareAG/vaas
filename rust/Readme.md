# gdata-vaas

An SDK to easily utilize G DATA VaaS.

_Verdict-as-a-Service_ (VaaS) is a service that provides a platform for scanning files for malware and other threats. It allows easy integration in your application. With a few lines of code, you can start scanning files for malware.

## What does the SDK do?

It gives you as a developer a functions to talk to G DATA VaaS. It wraps away the complexity of the API into 5 basic functions.

### for_sha256

If you calculate the sha256 for a file, you can request that sha256 against G DATA VaaS. It's the fastest way to get a verdict from our service. This requires the hash value to be known to the VaaS server.

### for_url

If you want to request if a file behind a URL is safe, you can specify the URL as well. Depending on the file size, the duration for the analysis can vary.

### for_file

You can also ask for a file itself. You will still get the benefit of a fast verdict via Sha256 because the SDK will do that for you first. But additionally, if we don't know the file, the file will get uploaded and (automatically) analyzed by us.

### for_stream

For data blobs which do not exist as a file on-disk, you can also supply the file as a binary data stream.

### for_buf

Effectively a simplified version of `for_stream`, you can supply a byte blob as a file.

## How to use

### Installation

```bash
cargo add vaas
```

### Examples
For more insights about the api, please check out our documentation on [Docs.rs](https://docs.rs/vaas/latest/vaas/).

## <a name="interested"></a>I'm interested in VaaS

You need credentials to use the service in your application. Please [check out the main project README for further information](https://github.com/GDATASoftwareAG/vaas/blob/main/Readme.md).