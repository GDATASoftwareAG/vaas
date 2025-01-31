package de.gdata.vaasexample;

import de.gdata.vaas.*;
import de.gdata.vaas.authentication.*;

import java.net.URI;


public class Authentication {
    public static void main(String[] args) throws Exception {
        var env = new Environment();

        var clientId = env.clientId;
        var clientSecret = env.clientSecret;
        var vaasclientId = env.vaasClientId;
        var userName = env.userName;
        var password = env.password;
        var tokenUrl = env.tokenUrl;
        var vaasUrl = env.vaasUrl;

        // If you got a username and password from us, you can use the ResourceOwnerPasswordAuthenticator like this
        var authenticator = new ResourceOwnerPasswordGrantAuthenticator(
                vaasclientId,
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
        var verdict = vaas.forSha256(new Sha256("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"));
        System.out.printf("File %s was detected as %s", verdict.getSha256(), verdict.getVerdict());
    }
}