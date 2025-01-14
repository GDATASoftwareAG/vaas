package de.gdata.vaas.authentication;

import de.gdata.vaas.exceptions.VaasAuthenticationException;
import lombok.Getter;
import org.jetbrains.annotations.NotNull;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;

public class ClientCredentialsGrantAuthenticator implements IAuthenticator {

    @Getter
    private final String clientId;
    @Getter
    private final String clientSecret;
    private final ClientCredentialsTokenReceiver tokenReceiver;

    /**
     * The authenticator for the client credentials grant type if you have a client id and client secret.
     *
     * @param clientId     The client id
     * @param clientSecret The client secret
     * @param tokenUrl     The optional token url. Defaults to the G DATA production URL
     * @param httpClient   Your optional custom http client.
     */
    public ClientCredentialsGrantAuthenticator(@NotNull String clientId, @NotNull String clientSecret, @NotNull URI tokenUrl, @NotNull HttpClient httpClient) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.tokenReceiver = new ClientCredentialsTokenReceiver(this, tokenUrl, httpClient);
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
    public String getToken() throws VaasAuthenticationException {
        return tokenReceiver.getToken();
    }
}