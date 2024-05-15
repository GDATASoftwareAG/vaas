package de.gdata.vaasexample;

import de.gdata.vaas.*;
import de.gdata.vaas.messages.VerdictRequestAttributes;

import java.net.URI;
import java.nio.file.Path;

public class Main {
    public static void main(String[] args) throws Exception {
        // Either set CLIENT_ID & CLIENT_SECRET or alternatively VAAS_USER_NAME and VAAS_PASSWORD
        var clientId = System.getenv("CLIENT_ID");
        var clientSecret = System.getenv("CLIENT_SECRET");
        var userName = System.getenv("VAAS_USER_NAME");
        var password = System.getenv("VAAS_PASSWORD");
        var scanPath = getenv("SCAN_PATH");
        var tokenUrl = System.getenv("TOKEN_URL");
        if (tokenUrl == null) {
            tokenUrl = "https://account-staging.gdata.de/realms/vaas-staging/protocol/openid-connect/token";
        }
        var vaasUrl = System.getenv("VAAS_URL");
        if (vaasUrl == null) {
            vaasUrl = "wss://gateway.staging.vaas.gdatasecurity.de";
        }

        IAuthenticator authenticator;
        if (clientId == null) {
            if (userName == null) {
                throw new IllegalStateException("Either CLIENT_ID or VAAS_USER_NAME must be set");
            }
            authenticator = new ResourceOwnerPasswordGrantAuthenticator("vaas-customer", userName, password, new URI(tokenUrl));
        } else {
            authenticator = new ClientCredentialsGrantAuthenticator(clientId, clientSecret, new URI(tokenUrl));
        }

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