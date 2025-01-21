package de.gdata.vaas.authentication;

import lombok.Getter;
import org.jetbrains.annotations.NotNull;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;

@Getter
public class ClientCredentialsGrantAuthenticator extends TokenReceiver implements IAuthenticator {

    private final String clientId;
    private final String clientSecret;
    private final URI tokenUrl;
    private final HttpClient httpClient;

    /**
     * The authenticator for the client credentials grant type if you have a client id and client secret.
     *
     * @param clientId     The client id
     * @param clientSecret The client secret
     * @param tokenUrl     The optional token url. Defaults to the G DATA production URL
     * @param httpClient   Your optional custom http client.
     */
    public ClientCredentialsGrantAuthenticator(@NotNull String clientId, @NotNull String clientSecret, @NotNull URI tokenUrl, @NotNull HttpClient httpClient) {
        super(tokenUrl, httpClient);
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.tokenUrl = tokenUrl;
        this.httpClient = httpClient;
    }

    /**
     * The authenticator for the client credentials grant type if you have a client id and client secret.
     *
     * @param clientId     The client id
     * @param clientSecret The client secret
     * @param tokenUrl     The optional token url. Defaults to the G DATA production URL
     */
    public ClientCredentialsGrantAuthenticator(@NotNull String clientId, @NotNull String clientSecret, @NotNull URI tokenUrl) {
        this(clientId, clientSecret, tokenUrl, HttpClient.newHttpClient());
    }

    /**
     * The authenticator for the client credentials grant type if you have a client id and client secret.
     *
     * @param clientId     The client id
     * @param clientSecret The client secret
     */
    public ClientCredentialsGrantAuthenticator(@NotNull String clientId, @NotNull String clientSecret) throws URISyntaxException {
        this(clientId, clientSecret, new URI("https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token"));
    }

    @Override
    protected String tokenRequestToForm() {
        return "client_id=" + URLEncoder.encode(this.getClientId(), StandardCharsets.UTF_8) +
                "&client_secret=" + URLEncoder.encode(this.getClientSecret(), StandardCharsets.UTF_8) +
                "&grant_type=client_credentials";
    }
}