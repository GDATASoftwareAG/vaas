package de.gdata.vaasexample;

import de.gdata.vaas.*;
import de.gdata.vaas.authentication.*;
import java.net.URI;
import java.net.URL;

public class ForUrlScan {
    public static void main(String[] args) throws Exception {
        IAuthenticator authenticator;
        var env = new Environment();
        if (env.clientId == null) {
            if (env.userName == null) {
                throw new IllegalStateException("Either CLIENT_ID or VAAS_USER_NAME must be set");
            }
            authenticator = new ResourceOwnerPasswordGrantAuthenticator("vaas-customer", env.userName, env.password, new URI(env.tokenUrl));
        } else {
            authenticator = new ClientCredentialsGrantAuthenticator(env.clientId, env.clientSecret, new URI(env.tokenUrl));
        }

        var config = new VaasConfig(new URI(env.vaasUrl));
        var vaas = new Vaas(config, authenticator);
        var url = new URL("https://secure.eicar.org/eicar.com.txt");
        var verdict = vaas.forUrl(url);
        System.out.printf("File %s was sync detected as %s", verdict.getSha256(), verdict.getVerdict());
        vaas.forUrlAsync(url).thenAccept(vaasResult -> {
            System.out.printf("\nFile %s was async detected as %s", vaasResult.getSha256(), vaasResult.getVerdict());
        }).get();

    }
}