# gdata-vaas

An SDK to easily utilize G DATA VaaS.

_Verdict-as-a-Service_ (VaaS) is a service that provides a platform for scanning files for malware and other threats. It allows easy integration in your application. With a few lines of code, you can start scanning files for malware.

    ATTENTION: This library is currently under heavy construction!

## What does the SDK do?

It gives you as a developer a functions to talk to G DATA VaaS. It wraps away the complexity of the API into 4 basic functions.

### forSha256

If you calculate the sha256 for a file, you can request that sha256 against G DATA VaaS. It's the fastest way to get a verdict from our service.

### forSha256List

You can also request multiple sha256 with a single function call.

### forFile

You can also ask for a file itself. You will still get the benefit of a fast verdict via Sha256 because the SDK will do that for you first. But additionally, if we don't know the file, the file will get uploaded and (automatically) analyzed by us.

### forFileList

You can also request multiple files with a single function call.

## How to use

### Install

```bash
npm install gdata-vaas
```

### Import

```typescript
import Vaas from "gdata-vaas";
```

### Request a verdict

```typescript
// create vaas client
const vaas = await createVaasWithClientCredentialsGrant(
    CLIENT_ID,
    CLIENT_SECRET,
    TOKEN_URL,
    VAAS_URL
  );
```

Are you interested in credentials? [Contact us](#interested).

```typescript
// request verdict for file
const verdict = await vaas.forFile(response.data);
if (verdict === "Malicious") {
  console.log("This was malware.");
}
```

## <a name="interested"></a>I'm interested in VaaS

You need credentials to use the service in your application. If you are interested in using VaaS, please [contact us](mailto:oem@gdata.de).

## Developing with Visual Studio Code

Required extensions:

- esbenp.prettier-vscode

Extend settings.json with:

```json
{
  "editor.formatOnSave": true,
  "[javascript]": {
    "editor.defaultFormatter": "esbenp.prettier-vscode"
  },
  "[typescript]": {
    "editor.defaultFormatter": "esbenp.prettier-vscode"
  }
}
```
