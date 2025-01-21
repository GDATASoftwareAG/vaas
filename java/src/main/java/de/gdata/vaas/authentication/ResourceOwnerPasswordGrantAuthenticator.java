package de.gdata.vaas.authentication;

import lombok.Getter;
import org.jetbrains.annotations.NotNull;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;

@Getter
public class ResourceOwnerPasswordGrantAuthenticator extends TokenReceiver implements IAuthenticator {

    private final String clientId;
    private final String userName;
    private final String password;

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
        super(tokenUrl, httpClient);
        this.clientId = clientId;
        this.userName = userName;
        this.password = password;
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
    protected String tokenRequestToForm() {
        return "client_id=" + URLEncoder.encode(this.getClientId(), StandardCharsets.UTF_8) +
                "&username=" + URLEncoder.encode(this.getUserName(), StandardCharsets.UTF_8) +
                "&password=" + URLEncoder.encode(this.getPassword(), StandardCharsets.UTF_8) +
                "&grant_type=password";
    }
}
