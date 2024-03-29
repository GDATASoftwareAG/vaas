package de.gdata.vaasexample;

import de.gdata.vaas.ClientCredentialsGrantAuthenticator;
import de.gdata.vaas.Vaas;
import de.gdata.vaas.VaasConfig;
import de.gdata.vaas.messages.VerdictRequestAttributes;

import java.net.URI;
import java.net.URL;

public class UrlScan {
    public static void main(String[] args) throws Exception {
        var clientId = System.getenv("CLIENT_ID");
        var clientSecret = System.getenv("CLIENT_SECRET");
        var tokenUrl = System.getenv("TOKEN_URL");
        if (tokenUrl == null) {
            tokenUrl = "https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token";
        }
        var vaasUrl = System.getenv("VAAS_URL");
        if (vaasUrl == null) {
            vaasUrl = "wss://gateway.production.vaas.gdatasecurity.de";
        } 

        var authenticator = new ClientCredentialsGrantAuthenticator(clientId, clientSecret, new URI(tokenUrl));
        var config = new VaasConfig(new URI(vaasUrl));
        var vaas = new Vaas(config, authenticator);
        vaas.connect();

        var url = new URL("https://secure.eicar.org/eicar.com");

        var verdictRequestAttributes = new VerdictRequestAttributes();
        verdictRequestAttributes.setTenantId("urlTenant");
        var verdict = vaas.forUrl(url, verdictRequestAttributes);

        vaas.disconnect();
        System.out.printf("File %s was detected as %s", verdict.getSha256(), verdict.getVerdict());
    }
}