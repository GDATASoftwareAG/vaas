package de.gdata.test.unit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.net.URI;
import java.net.URISyntaxException;

import org.junit.jupiter.api.Test;

import de.gdata.vaas.authentication.ClientCredentialsGrantAuthenticator;
import de.gdata.vaas.authentication.IAuthenticator;
import de.gdata.vaas.authentication.ResourceOwnerPasswordGrantAuthenticator;
import io.github.cdimascio.dotenv.Dotenv;

public class AuthenticatorTest {
    private static final Dotenv dotenv = Dotenv.configure()
            .ignoreIfMissing()
            .load();

    private static String getEnvironmentKey(String key) {
        var value = dotenv.get(key);
        if (value == null) {
            throw new IllegalArgumentException("Environment variable " + key + " must be set.");
        }
        return value;
    }

    @Test
    public void clientCredentialsGrantAuthenticator_GetToken() throws Exception {
        var clientId = getEnvironmentKey("CLIENT_ID");
        var clientSecret = getEnvironmentKey("CLIENT_SECRET");
        var tokenUrl = new URI(getEnvironmentKey("TOKEN_URL"));
        var authenticator = new ClientCredentialsGrantAuthenticator(clientId, clientSecret, tokenUrl);
        var token = authenticator.getToken();

        assertNotNull(token);
    }

    @Test
    public void clientCredentialsGrantAuthenticator_GetCachedToken() throws Exception {
        var clientId = getEnvironmentKey("CLIENT_ID");
        var clientSecret = getEnvironmentKey("CLIENT_SECRET");
        var tokenUrl = new URI(getEnvironmentKey("TOKEN_URL"));
        var authenticator = new ClientCredentialsGrantAuthenticator(clientId, clientSecret, tokenUrl);
        var token = authenticator.getToken();
        var cachedToken = authenticator.getToken();

        assertEquals(token, cachedToken);
    }

    @Test
    public void resourceOwnerPasswordAuthenticator_GetToken() throws Exception {
        var clientId = getEnvironmentKey("VAAS_CLIENT_ID");
        var username = getEnvironmentKey("VAAS_USER_NAME");
        var password = getEnvironmentKey("VAAS_PASSWORD");
        var tokenUrl = new URI(getEnvironmentKey("TOKEN_URL"));
        var authenticator = new ResourceOwnerPasswordGrantAuthenticator(clientId, username, password, tokenUrl);
        var token = authenticator.getToken();

        assertNotNull(token);
    }

    @Test
    public void resourceOwnerPasswordAuthenticator_GetCachedToken() throws Exception {
        var clientId = getEnvironmentKey("VAAS_CLIENT_ID");
        var username = getEnvironmentKey("VAAS_USER_NAME");
        var password = getEnvironmentKey("VAAS_PASSWORD");
        var tokenUrl = new URI(getEnvironmentKey("TOKEN_URL"));
        var authenticator = new ResourceOwnerPasswordGrantAuthenticator(clientId, username, password, tokenUrl);
        var token = authenticator.getToken();
        var cachedToken = authenticator.getToken();

        assertEquals(token, cachedToken);
    }
}
