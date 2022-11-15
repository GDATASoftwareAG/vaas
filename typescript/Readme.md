# gdata-vaas

An SDK to easily utilize G DATA VaaS.

_Verdict-as-a-Service_ (VaaS) is a service that provides a platform for scanning files for malware and other threats. It allows easy integration in your application. With a few lines of code, you can start scanning files for malware.

## What does the SDK do?

It gives you as a developer a functions to talk to G DATA VaaS. It wraps away the complexity of the API into 5 basic functions.

### forSha256

If you calculate the sha256 for a file, you can request that sha256 against G DATA VaaS. It's the fastest way to get a verdict from our service.

### forSha256List

You can also request multiple sha256 with a single function call.

### forUrl

If you want to request if a file behind a URL is safe, you can specify the URL as well. Depending on the file size, the duration for the analysis can vary.

### forFile

You can also ask for a file itself. You will still get the benefit of a fast verdict via Sha256 because the SDK will do that for you first. But additionally, if we don't know the file, the file will get uploaded and (automatically) analyzed by us.

### forFileList

You can also request multiple files with a single function call.

## How to use

### Installation

```bash
npm install gdata-vaas
```

### Import

```typescript
import { ClientCredentialsGrantAuthenticator, Vaas } from "gdata-vaas";
```

### Request a verdict

Authentication & Initializing:
```typescript
let authenticator = new ClientCredentialsGrantAuthenticator(
    CLIENT_ID,
    CLIENT_SECRET,
    TOKEN_URL
);
let vaas = new Vaas();
let token = await authenticator.getToken()
await vaas.connect(token, VAAS_URL)
```

Verdict Request for SHA256:
```typescript
const sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
const verdict = await vaas.forSha256(sha256);
if (verdict.verdict === "Malicious") {
  console.log("This was malware.");
}
```

Verdict Request for a file:
```typescript
const verdict = await vaas.forFile(response.data);
if (verdict.verdict === "Malicious") {
  console.log("This was malware.");
}
```

Verdict Request for a URL:
```typescript
const verdict = await vaas.forUrl(
  new URL("https://www.gdatasoftware.com/oem/verdict-as-a-service"));
if (verdict.verdict === "Clean") {
  console.log("This URL is clean.");
}
```

## <a name="interested"></a>I'm interested in VaaS

You need credentials to use the service in your application. If you are interested in using VaaS, please [contact us](mailto:oem@gdata.de).

## Developing with Visual Studio Code

Every single SDKs also includes [Devcontainer](./devcontainer/). If you use the [Visual Studio Code Dev Containers extension](https://code.visualstudio.com/docs/devcontainers/containers), you can run the code in a full-featured development environment.