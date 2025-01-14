package de.gdata.vaas.authentication;

import org.jetbrains.annotations.NotNull;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;

class ResourceOwnerPasswordTokenReceiver extends TokenReceiver {

    private final ResourceOwnerPasswordGrantAuthenticator authenticator;

    public ResourceOwnerPasswordTokenReceiver(ResourceOwnerPasswordGrantAuthenticator authenticator, @NotNull URI tokenUrl, @NotNull HttpClient httpClient) {
        super(authenticator, tokenUrl, httpClient);
        this.authenticator = authenticator;
    }

    public ResourceOwnerPasswordTokenReceiver(ResourceOwnerPasswordGrantAuthenticator authenticator, @NotNull URI tokenUrl) {
        super(authenticator, tokenUrl);
        this.authenticator = authenticator;
    }

    public ResourceOwnerPasswordTokenReceiver(ResourceOwnerPasswordGrantAuthenticator authenticator) throws URISyntaxException {
        super(authenticator);
        this.authenticator = authenticator;
    }

    @Override
    protected String tokenRequestToForm() {
        return "client_id=" + URLEncoder.encode(authenticator.getClientId(), StandardCharsets.UTF_8) +
                "&username=" + URLEncoder.encode(authenticator.getUserName(), StandardCharsets.UTF_8) +
                "&password=" + URLEncoder.encode(authenticator.getPassword(), StandardCharsets.UTF_8) +
                "&grant_type=password";
    }
}