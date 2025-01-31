package de.gdata.vaasexample;

import de.gdata.vaas.*;
import de.gdata.vaas.authentication.*;
import java.net.URI;

import java.nio.file.Files;
import java.nio.file.Path;

public class ForStreamScan {
    public static void main(String[] args) throws Exception {
        var env = new Environment();

        var authenticator = new ClientCredentialsGrantAuthenticator(env.clientId, env.clientSecret, new URI(env.tokenUrl));
        var config = new VaasConfig(new URI(env.vaasUrl));
        var vaas = new Vaas(config, authenticator);

        try (var inputStream = Files.newInputStream(Path.of(Environment.getenv("SCAN_PATH")))) {
            var verdict = vaas.forStream(inputStream, Path.of(Environment.getenv("SCAN_PATH")).toFile().length());
            System.out.printf("File %s was sync detected as %s", verdict.getSha256(), verdict.getVerdict());
        }

        try (var inputStream = Files.newInputStream(Path.of(Environment.getenv("SCAN_PATH")))) {
            vaas.forStreamAsync(inputStream, Path.of(Environment.getenv("SCAN_PATH")).toFile().length()).thenAccept(vaasResult -> {
                System.out.printf("\nFile %s was async detected as %s", vaasResult.getSha256(), vaasResult.getVerdict());
            }).get();
        }
    }
}