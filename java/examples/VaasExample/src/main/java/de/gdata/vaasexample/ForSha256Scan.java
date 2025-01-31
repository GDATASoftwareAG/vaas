package de.gdata.vaasexample;

import de.gdata.vaas.*;
import de.gdata.vaas.authentication.*;
import java.net.URI;

public class ForSha256Scan {
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
        var sha256 = new Sha256("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
        var verdict = vaas.forSha256(sha256);
        System.out.printf("File %s was sync detected as %s", verdict.getSha256(), verdict.getVerdict());
        vaas.forSha256Async(sha256).thenAccept(vaasResult -> {
            System.out.printf("\nFile %s was async detected as %s", vaasResult.getSha256(), vaasResult.getVerdict());
        }).get();

    }
}