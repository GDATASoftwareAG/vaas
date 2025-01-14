package de.gdata.vaas.authentication;

import de.gdata.vaas.exceptions.VaasAuthenticationException;
import lombok.Getter;
import org.jetbrains.annotations.NotNull;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;

public class ResourceOwnerPasswordGrantAuthenticator implements IAuthenticator {

    @Getter
    private final String clientId;
    @Getter
    private final String userName;
    @Getter
    private final String password;
    private final ResourceOwnerPasswordTokenReceiver tokenReceiver;

    /**
     * The authenticator for the resource owner password grant type if you have a client id, username and password.
     * This is the choice if you have registered yourself on the <a href="https://vaas.gdata.de/login">registration page</a>. In this case, the client id is `vaas-customer`.
     *
     * @param clientId   The client id
     * @param userName   Your username or email
     * @param password   Your password
     * @param tokenUrl   The optional token url. Defaults to the <a href="https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token">G DATA production URL</a>
     * @param httpClient Your optional custom http client.
     */
    public ResourceOwnerPasswordGrantAuthenticator(@NotNull String clientId, @NotNull String userName, @NotNull String password, @NotNull URI tokenUrl, @NotNull HttpClient httpClient) {
        this.clientId = clientId;
        this.userName = userName;
        this.password = password;
        this.tokenReceiver = new ResourceOwnerPasswordTokenReceiver(this, tokenUrl, httpClient);
    }

    /**
     * The authenticator for the resource owner password grant type if you have a client id, username and password.
     * This is the choice if you have registered yourself on the <a href="https://vaas.gdata.de/login">registration page</a>. In this case, the client id is `vaas-customer`.
     *
     * @param clientId The client id
     * @param userName Your username or email
     * @param password Your password
     * @param tokenUrl The optional token url. Defaults to the <a href="https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token">G DATA production URL</a>
     */
    public ResourceOwnerPasswordGrantAuthenticator(@NotNull String clientId, @NotNull String userName, @NotNull String password, @NotNull URI tokenUrl) {
        this(clientId, userName, password, tokenUrl, HttpClient.newHttpClient());
    }

    /**
     * The authenticator for the resource owner password grant type if you have a client id, username and password.
     * This is the choice if you have registered yourself on the <a href="https://vaas.gdata.de/login">registration page</a>. In this case, the client id is `vaas-customer`.
     *
     * @param clientId The client id
     * @param userName Your username or email
     * @param password Your password
     */
    public ResourceOwnerPasswordGrantAuthenticator(@NotNull String clientId, @NotNull String userName, @NotNull String password) throws URISyntaxException {
        this(clientId, userName, password, new URI("https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token"));
    }

    @Override
    public String getToken() throws VaasAuthenticationException {
        return tokenReceiver.getToken();
    }
}
