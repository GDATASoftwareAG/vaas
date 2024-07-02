# vaas-scan-action

This is a github action with that one can scan changes in pull-requests with the G DATA product Verdict-as-a-Service (VaaS). VaaS is an Antivirus in the cloud, that can be utilized by a simple api.

## preconditions

Before you can use this action, you need to aquire credentials. Please find more Information on the [Verdict-as-a-Service product page](https://www.gdata.de/business/security-services/verdict-as-a-service). If you want to test VaaS on your own, you can get credentials on our [registration page](https://vaas.gdata.de/)

## usage

```yaml
- uses: actions/vaas-scan-action
  with:
    # You either need VAAS_CLIENT_ID (get in contact with us) or a VAAS_USERNAME (use the self registration (trial))
    # The CLIENT_ID is the only mendatory variable
    VAAS_CLIENT_ID: "some-id"
    # A CLIENT_SECRET is only required when you got in contact with us
    VAAS_CLIENT_SECRET: "some-secret"
    # The USERNAME can be optained on our registration page
    VAAS_USERNAME: "some-username"
    # The PASSWORD can be optained on our registration page
    VAAS_PASSWORD: "some-password"
    # You can point the VAAS_URL to a self-hosted version of VaaS. If you need that, please get in contact with us.
    VAAS_URL: "wss://gateway.production.vaas.gdatasecurity.de/"
    # This is the token-endpoint of VaaS. For self-hosted versions, you need to change this url too.
    VAAS_TOKEN_URL: "https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token"
```

## scenarios

### Self-Registered Credentials

```yaml
- uses: actions/vaas-scan-action
  with:
    VAAS_USERNAME: "some-username"
    VAAS_PASSWORD: "some-password"
```

### Got a CLIENT_SECRET from us

```yaml
- uses: actions/vaas-scan-action
  with:
    VAAS_CLIENT_ID: "some-id"
    VAAS_CLIENT_SECRET: "some-secret"
```

### For on Premise VaaS installations

```yaml
- uses: actions/vaas-scan-action
  with:
    VAAS_CLIENT_ID: "some-id"
    VAAS_CLIENT_SECRET: "some-secret"
    VAAS_URL: "wss://myselfhostedvaas/"
    VAAS_TOKEN_URL: "https://myselfhostedidentityprovider/realms/vaas/protocol/openid-connect/token"
```