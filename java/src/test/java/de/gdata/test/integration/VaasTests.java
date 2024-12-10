package de.gdata.test.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import de.gdata.vaas.ClientCredentialsGrantAuthenticator;
import de.gdata.vaas.Sha256;
import de.gdata.vaas.Vaas;
import de.gdata.vaas.VaasConfig;
import de.gdata.vaas.exceptions.VaasAuthenticationException;
import de.gdata.vaas.messages.Verdict;
import io.github.cdimascio.dotenv.Dotenv;

public class VaasTests {
    private static final Dotenv dotenv = Dotenv.configure()
            .ignoreIfMissing()
            .load();

    private static Vaas vaas;

    @BeforeAll
    public static void setUpAll() throws URISyntaxException, InterruptedException, IOException, ExecutionException,
            TimeoutException, VaasAuthenticationException {
        vaas = getVaasWithCredentials();
    }

    private static String getEnvironmentKey(String key) {
        var value = dotenv.get(key);
        if (value == null) {
            throw new IllegalArgumentException("Environment variable " + key + " must be set.");
        }
        return value;
    }

    private static Vaas getVaasWithCredentials()
            throws URISyntaxException, InterruptedException, IOException, ExecutionException, TimeoutException,
            VaasAuthenticationException {
        var clientId = getEnvironmentKey("CLIENT_ID");
        var clientSecret = getEnvironmentKey("CLIENT_SECRET");
        var tokenUrl = new URI(getEnvironmentKey("TOKEN_URL"));
        var vaasUrl = getEnvironmentKey("VAAS_URL");

        var authenticator = new ClientCredentialsGrantAuthenticator(clientId, clientSecret, tokenUrl);
        var config = new VaasConfig(new URI(vaasUrl));
        var vaas = new Vaas(config, authenticator);
        return vaas;
    }
    @Test
    public void forSha256SingleMaliciousHash() throws Exception {
        var sha256 = new Sha256("ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2");

        var verdict = vaas.forSha256(sha256).join();

        assertEquals(Verdict.MALICIOUS, verdict.getVerdict());
        assertTrue("ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2"
                .equalsIgnoreCase(verdict.getSha256()));
    }

    @Test
    public void forFileSingleMaliciousHash() throws Exception {
        var sha256 = new Sha256("ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2");

        var verdict = vaas.forSha256(sha256).join();

        assertEquals(Verdict.MALICIOUS, verdict.getVerdict());
        assertTrue("ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2"
                .equalsIgnoreCase(verdict.getSha256()));
    }
    
    @Test
    public void forStreamSingleMaliciousHash() throws Exception {
        var sha256 = new Sha256("ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2");

        var verdict = vaas.forSha256(sha256).join();

        assertEquals(Verdict.MALICIOUS, verdict.getVerdict());
        assertTrue("ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2"
                .equalsIgnoreCase(verdict.getSha256()));
    }
    
    @Test
    public void forUrlSingleMaliciousHash() throws Exception {
        var sha256 = new Sha256("ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2");

        var verdict = vaas.forSha256(sha256).join();

        assertEquals(Verdict.MALICIOUS, verdict.getVerdict());
        assertTrue("ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2"
                .equalsIgnoreCase(verdict.getSha256()));
    }    
}
