package de.gdata.vaasexample;

import de.gdata.vaas.ClientCredentialsGrantAuthenticator;
import de.gdata.vaas.Vaas;
import de.gdata.vaas.VaasConfig;
import de.gdata.vaas.messages.VerdictRequestAttributes;

import java.net.URI;
import java.nio.file.Path;

public class Main {
    public static void main(String[] args) throws Exception {
        var clientId = getenv("CLIENT_ID");
        var clientSecret = getenv("CLIENT_SECRET");
        var scanPath = getenv("SCAN_PATH");
        var tokenUrl = System.getenv("TOKEN_URL");
        if (tokenUrl == null) {
            tokenUrl = "https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token";
        }
        var vaasUrl = System.getenv("VAAS_URL");
        if (vaasUrl == null) {
            vaasUrl = "wss://gateway.production.vaas.gdatasecurity.de";
        } 

        var authenticator = new ClientCredentialsGrantAuthenticator(clientId, clientSecret, new URI(tokenUrl));
        var config = new VaasConfig(
                new URI(vaasUrl));
        var vaas = new Vaas(config, authenticator);
        vaas.connect();

        var file = Path.of(scanPath);
        var verdictRequestAttributes = new VerdictRequestAttributes();
        verdictRequestAttributes.setTenantId("fileTenant");
        var verdict = vaas.forFile(file, verdictRequestAttributes);
        vaas.disconnect();
        System.out.printf("File %s was detected as %s", verdict.getSha256(), verdict.getVerdict());
    }

    public static String getenv(String key) {
        var value = System.getenv(key);
        if (value == null) {
            throw new IllegalStateException("The environment variable " + key + " must be set.");
        }
        return value;
    }
}