package de.gdata.vaasexample;

import de.gdata.vaas.*;
import de.gdata.vaas.authentication.*;
import java.net.URI;
import java.net.URL;

public class ForUrlScan {
    public static void main(String[] args) throws Exception {
        var env = new Environment();

        var authenticator = new ClientCredentialsGrantAuthenticator(env.clientId, env.clientSecret, new URI(env.tokenUrl));
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