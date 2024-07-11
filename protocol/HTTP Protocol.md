# Verdict-as-a-Service HTTP API

    This document describes the VaaS HTTP API. All SDKs have to implement this protocol to be able to use the VaaS HTTP API.

    Protocol version: 0.1.0

## API reference

The API is described in detail in the [OpenAPI specification](https://upload.staging.vaas.gdatasecurity.de/swagger/index.html).

## Authentication

The authentication and authorization works with a bearer token, that is requested from an OpenID Connect compatible
identity provider. 

The token MUST be reused for every HTTP request until it expires. For parallel requests the same token SHOULD be used.

## Request sequences

### Get a verdict for a hash

The verdict for a hash requires only 1 request.

* Get the report for the SHA256: GET https://upload.staging.vaas.gdatasecurity.de/files/{SHA256}/report
* The response body is a JSON object

```json
{
    "sha256":"3f1a417e7eb795da7bd034a94ecc0a61c30f4e4f1c2adc133292a6f2421e2332",
    "verdict":"Clean"
}
```

### Get a verdict for a file

Getting the verdict for a file requires multiple steps:

* Calculate the SHA256 hash of the file
* Get the report for the SHA256: GET https://upload.staging.vaas.gdatasecurity.de/files/{SHA256}/report
* The response body is a JSON object

```json
{
    "sha256":"3f1a417e7eb795da7bd034a94ecc0a61c30f4e4f1c2adc133292a6f2421e2332",
    "verdict":"Clean"
}
```

* If the verdict for the file is Unknown
  * Upload the file with PUT https://upload.staging.vaas.gdatasecurity.de/files
  * Get the report for the SHA256: GET https://upload.staging.vaas.gdatasecurity.de/files/{SHA256>}/report
