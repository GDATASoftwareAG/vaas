package de.gdata.vaas.authentication;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;

class ClientCredentialsTokenReceiver extends TokenReceiver {

    private final ClientCredentialsGrantAuthenticator authenticator;

    public ClientCredentialsTokenReceiver(ClientCredentialsGrantAuthenticator authenticator, URI tokenUrl, HttpClient httpClient) {
        super(authenticator, tokenUrl, httpClient);
        this.authenticator = authenticator;
    }

    public ClientCredentialsTokenReceiver(ClientCredentialsGrantAuthenticator authenticator, URI tokenUrl) {
        super(authenticator, tokenUrl);
        this.authenticator = authenticator;
    }

    public ClientCredentialsTokenReceiver(ClientCredentialsGrantAuthenticator authenticator) throws URISyntaxException {
        super(authenticator);
        this.authenticator = authenticator;
    }

    @Override
    protected String tokenRequestToForm() {
        return "client_id=" + URLEncoder.encode(authenticator.getClientId(), StandardCharsets.UTF_8) +
                "&client_secret=" + URLEncoder.encode(authenticator.getClientSecret(), StandardCharsets.UTF_8) +
                "&grant_type=client_credentials";
    }
}
