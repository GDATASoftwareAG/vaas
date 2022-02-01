# Verdict-as-a-Service Rust SDK

Scan files for malware and other threats using the VaaS API in Rust.

## Integration Test: Real API

Currently all test under the [/tests](./tests) folder are integration tests against the real API.
As they need credentials, (user, token) these need to be provided as environment variables.

Either export a `VAAS_USER` and `VAAS_TOKEN` environment variable or use the `.env` file. To use an `.env` file, just create it in the root directory (e.g. where the `Cargo.toml` resides) and add the variables with their values, e.g. `KEY=VALUE`.

The `.env` file will not be checked in into *git* and can be used to store the sensitive environment variables on your local machine.