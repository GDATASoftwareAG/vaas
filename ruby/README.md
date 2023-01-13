# vaas

An SDK to easily utilize G DATA VaaS.

_Verdict-as-a-Service_ (VaaS) is a service that provides a platform for scanning files for malware and other threats. It allows easy integration in your application. With a few lines of code, you can start scanning files for malware.

## What does the SDK do?

It gives you as a developer a functions to talk to G DATA VaaS. It wraps away the complexity of the API into 3 basic functions.

### for_sha256

If you calculate the sha256 for a file, you can request that sha256 against G DATA VaaS. It's the fastest way to get a verdict from our service.

### for_url

If you want to request if a file behind a URL is safe, you can specify the URL as well. Depending on the file size, the duration for the analysis can vary.

### for_file

You can also ask for a file itself. You will still get the benefit of a fast verdict via Sha256 because the SDK will do that for you first. But additionally, if we don't know the file, the file will get uploaded and (automatically) analyzed by us.

## How to use

### Installation

This gem works only on a Linux distribution!
```bash
gem install vaas
```

### Require

```ruby
require 'async'
require 'vaas/client_credentials_grant_authenticator'
require 'vaas/vaas_main'
```

### Request a verdict

Authentication & Initializing:
```ruby
authenticator = VAAS::ClientCredentialsGrantAuthenticator.new(
  CLIENT_ID,
  CLIENT_SECRET,
  TOKEN_URL,
  SSL_VERIFICATION
)
vaas = VAAS::VaasMain.new
token = authenticator.get_token
```

Verdict Request for SHA256:
```ruby
Async do
  Async { vaas.connect(token) }.wait
  sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
  verdict = vaas.for_sha256(sha256)
ensure
  vaas.close
end
```

Verdict Request for a file:
```ruby
Async do
  Async { vaas.connect(token) }.wait
  path = "/path/to/file"
  verdict = vaas.for_file(path)
ensure
  vaas.close
end
```

Verdict Request for a URL:
```ruby
Async do
  Async { vaas.connect(token) }.wait
  url = "https://www.gdatasoftware.com/oem/verdict-as-a-service"
  verdict = vaas.for_url(url)
ensure
  vaas.close
end
```

Verdict Object:
```ruby
# A verdict object has a sha256, verdict and guid
sha256 = verdict.sha256
detection = verdict.verdict
guid = verdict.guid
```

## <a name="interested"></a>I'm interested in VaaS

You need credentials to use the service in your application. If you are interested in using VaaS, please [contact us](mailto:oem@gdata.de).
