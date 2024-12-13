package de.gdata.test.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
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
import de.gdata.vaas.options.ForStreamOptions;
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
    public void forSha256_ReturnsVerdict() throws Exception {
        var sha256 = new Sha256("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");

        var verdict = vaas.forSha256(sha256).join();

        assertEquals(Verdict.MALICIOUS, verdict.getVerdict());
        assertTrue("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                .equalsIgnoreCase(verdict.getSha256()));
    }

    @Test
    public void forFile_ReturnsVerdict() throws Exception {
        var tmpFile = Path.of(System.getProperty("java.io.tmpdir"), "eicar.txt");
        var url = new URL("https://secure.eicar.org/eicar.com.txt");
        var conn = url.openConnection();
        var inputStream = conn.getInputStream();
        Files.copy(inputStream, tmpFile, StandardCopyOption.REPLACE_EXISTING);

        var verdict = vaas.forFile(tmpFile).join();

        assertEquals(Verdict.MALICIOUS, verdict.getVerdict());
        assertTrue("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                .equalsIgnoreCase(verdict.getSha256()));
    }

    @Test
    public void forStream_ReturnsVerdict() throws Exception {
        var url = new URL("https://secure.eicar.org/eicar.com.txt");
        var conn = url.openConnection();
        var inputStream = conn.getInputStream();
        var contentLength = conn.getContentLength();
        var forStreamOptions = new ForStreamOptions(true, "foobar");

        var verdict = vaas.forStream(inputStream, contentLength, forStreamOptions).join();

        assertEquals(Verdict.MALICIOUS, verdict.getVerdict());
        assertTrue("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                .equalsIgnoreCase(verdict.getSha256()));
    }

    @Test
    public void forUrl_ReturnsVerdict() throws Exception {
        var url = new URL("https://secure.eicar.org/eicar.com.txt");

        var verdict = vaas.forUrl(url).join();

        assertEquals(Verdict.MALICIOUS, verdict.getVerdict());
        assertTrue("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                .equalsIgnoreCase(verdict.getSha256()));
    }
}
