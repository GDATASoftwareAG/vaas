# gdata-vaas

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

## What do the Verdicts look like

The verdicts are simple. They are either
- `Clean`: The scanners didn't find anything malicious.
- `Malicious`: The scanners found something malicious.
- `Unknown`: We don't know the file hash yet. A scan is then performed for each except `for_sha256` function.
- `Pup`: Potentially Unwanted Program (Adware, Spyware, etc.)

The scan functions will return the following dict:
```python
{
    "Sha256": "<Sha256>",
    "Guid": "<Guid>",
    "Verdict": <"Clean"|"Malicious"|"Unknown"|"Pup">,
    "Detection": "<Name of the detected malware>",
    "FileType": "<FileType>",
    "MimeType": "<MimeType>"
}
```

## How to use

### Installation

```bash
pip3 install gdata-vaas
```

### Import

```python
from vaas import Vaas, ClientCredentialsGrantAuthenticator
```

### Request a verdict

Authentication & Initializing:
```python
authenticator = ClientCredentialsGrantAuthenticator(
    CLIENT_ID,
    CLIENT_SECRET,
    TOKEN_URL,
    SSL_VERIFICATION
)
```

Verdict Request for SHA256:
```python
async with Vaas() as vaas:
    await vaas.connect(await authenticator.get_token())
    sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    verdict = await vaas.for_sha256(sha256)
```

Verdict Request for a file:
```python
async with Vaas() as vaas:
    await vaas.connect(await authenticator.get_token())
    path = "/path/to/file"
    verdict = await vaas.for_file(path)
```

Verdict Request for a URL:
```python
async with Vaas() as vaas:
    await vaas.connect(await authenticator.get_token())
    url = "https://www.gdatasoftware.com/oem/verdict-as-a-service"
    verdict = await vaas.for_url(url)
```

## <a name="interested"></a>I'm interested in VaaS

You need credentials to use the service in your application. If you are interested in using VaaS, please [contact us](mailto:oem@gdata.de).

## Developing with Visual Studio Code

Every single SDKs also includes [Devcontainer](./devcontainer/). If you use the [Visual Studio Code Dev Containers extension](https://code.visualstudio.com/docs/devcontainers/containers), you can run the code in a full-featured development environment.