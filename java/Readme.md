# Verdict-as-a-Service Java SDK

Scan files for malware and other threats using the VaaS API in Java.

## Usage

Get a verdict for a SHA256 of a file.

```java
public class MainClass {
    public static void main(String[] args) {
        // Connect to the VaaS endpoint
        var authenticator = new ClientCredentialsGrantAuthenticator(clientId, clientSecret, tokenUrl);
        var config = new VaasConfig(new URI(tokenUrl), new URI(vaasUrl));
        var client = new Vaas(config, authenticator);
        client.connect();

        // Get a verdict for a SHA256
        var sha256 = new Sha256("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8");
        var verdict = client.forSha256(sha256);

        // Disconnect from the VaaS endpoint
        client.disconnect();

        // Print verdict result (CLEAN, UNKNOWN, MALICIOUS, PUP)
        System.out.println("Verdict: " + verdict.getVerdict().name());
    }
}

```

Get a verdict for a file.

```java
public class MainClass {
    public static void main(String[] args) {
        // Connect to the VaaS endpoint
        var authenticator = new ClientCredentialsGrantAuthenticator(clientId, clientSecret, tokenUrl);
        var config = new VaasConfig(new URI(tokenUrl), new URI(vaasUrl));
        var client = new Vaas(config, authenticator);
        client.connect();

        // Get a verdict for a SHA256
        var file = Path.of("myfile");
        var verdict = client.forFile(file);

        // Disconnect from the VaaS endpoint
        client.disconnect();

        // Print verdict result (CLEAN, UNKNOWN, MALICIOUS, PUP)
        System.out.println("Verdict: " + verdict.getVerdict().name());
    }
}
```