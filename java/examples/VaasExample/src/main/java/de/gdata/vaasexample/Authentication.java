package de.gdata.vaasexample;

import de.gdata.vaas.ClientCredentialsGrantAuthenticator;
import de.gdata.vaas.ResourceOwnerPasswordGrantAuthenticator;
import de.gdata.vaas.Vaas;
import de.gdata.vaas.VaasConfig;
import de.gdata.vaas.messages.VerdictRequestAttributes;
import java.net.URI;
import java.nio.file.Path;


public class Authentication {
    public static void main(String[] args) throws Exception {
        var clientId = System.getenv("CLIENT_ID");
        var clientSecret = System.getenv("CLIENT_SECRET");
        var userName = System.getenv("VAAS_USER_NAME");
        var password = System.getenv("VAAS_PASSWORD");
        var scanPath = System.getenv("SCAN_PATH");
        var tokenUrl = System.getenv("TOKEN_URL");
        if (tokenUrl == null) { tokenUrl = "https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token"; }
        var vaasUrl = System.getenv("VAAS_URL");
        if (vaasUrl == null) { vaasUrl = "wss://gateway.production.vaas.gdatasecurity.de"; }

        // If you got a username and password from us, you can use the ResourceOwnerPasswordAuthenticator like this
        var authenticator = new ResourceOwnerPasswordGrantAuthenticator(
                "vaas-customer",
                userName,
                password,
                new URI(tokenUrl)
        );
        // You may use self registration and create a new username and password for the
        // ResourceOwnerPasswordAuthenticator by yourself like the example above on https://vaas.gdata.de/login

        // Else if you got a client id and client secret from us, you can use the ClientCredentialsGrantAuthenticator like this
        // var authenticator = new ClientCredentialsGrantAuthenticator(
        //         clientId,
        //         clientSecret,
        //         new URI(tokenUrl)
        // );

        var config = new VaasConfig(new URI(vaasUrl));
        var vaas = new Vaas(config, authenticator);
        vaas.connect();

        var file = Path.of(scanPath);
        var verdictRequestAttributes = new VerdictRequestAttributes();
        verdictRequestAttributes.setTenantId("fileTenant");
        var verdict = vaas.forFile(file, verdictRequestAttributes);
        vaas.disconnect();
        System.out.printf("File %s was detected as %s", verdict.getSha256(), verdict.getVerdict());
    }
}