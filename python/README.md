# gdata-vaas

An SDK to easily utilize G DATA VaaS. 

*Verdict-as-a-Service* (VaaS) is a service that provides a platform for scanning files for malware and other threats. It allows easy integration in your application. With a few lines of code, you can start scanning files for malware. 

    ATTENTION: This library is currently under heavy construction!

## What does the SDK do?

It gives you as a developer a functions to talk to G DATA VaaS. It wraps away the complexity of the API into 4 basic functions.

## How to use

### Install

```bash
pip3 install gdata-vaas
```
### Example: Request a verdict for file

```python
        async with Vaas() as vaas:
            await vaas.connect(TOKEN)
            buffer = base64.b64decode(EICAR_BASE64)
            verdict = await vaas.for_buffer(buffer)
```

### Request a verdict

Interested in a token? [Contact us](#interested).



## <a name="interested"></a>I'm interested in VaaS

You need credentials to use the service in your application. If you are interested in using VaaS, please [contact us](mailto:oem@gdata.de).
