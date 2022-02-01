# Verdict-as-a-Service Java SDK

Scan files for malware and other threats using the VaaS API in Java.

## Usage

Get a verdict for a SHA256 of a file.
```java
public class MainClass {
    public  static void main(String[] args) {
        // Connect to the VaaS endpoint
        var config = new WsConfig(token);
        var vaas = new Vaas(config);
        vaas.connect();

        // Get a verdict for a SHA256
        var sha256 = new Sha256("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8");
        var cts = new CancellationTokenSource(Duration.ofSeconds(10));
        var verdict = vaas.forSha256(sha256, cts);

        // Disconnect from the VaaS endpoint
        vaas.disconnect();

        // Print verdict result (CLEAN, UNKNOWN, MALICIOUS)
        System.out.println("Verdict: " + verdict.getClassification().name());
    }
}

```

Get a verdict for a file.
```java
public class MainClass {
    public  static void main(String[] args) {
        // Connect to the VaaS endpoint
        var config = new WsConfig(token);
        var vaas = new Vaas(config);
        vaas.connect();

        // Get a verdict for a SHA256
        var file = Path.of("myfile");
        var cts = new CancellationTokenSource(Duration.ofSeconds(10));
        var verdict = vaas.forFile(file, cts);

        // Disconnect from the VaaS endpoint
        vaas.disconnect();

        // Print verdict result (CLEAN, UNKNOWN, MALICIOUS)
        System.out.println("Verdict: " + verdict.getClassification().name());
    }
}
```

## Integration Test: Real API
Currently, all test under the /src/test folder are integration tests against the real API. As they need credentials, (token). These values need to be provided as environment variables.

Either export a VAAS_TOKEN environment variable or use the .env file. To use an .env file, just create it in the root directory (e.g. where the Readme.md resides) and add the variables with their values, e.g. KEY=VALUE.

The .env file will not be checked in into git and can be used to store the sensitive environment variables on your local machine.