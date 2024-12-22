package de.gdata.test.integration;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.testng.AssertJUnit.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;
import java.util.Optional;

import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import de.gdata.test.unit.Sha256Test;
import de.gdata.vaas.ClientCredentialsGrantAuthenticator;
import de.gdata.vaas.IAuthenticator;
import de.gdata.vaas.ResourceOwnerPasswordGrantAuthenticator;
import de.gdata.vaas.Sha256;
import de.gdata.vaas.Vaas;
import de.gdata.vaas.VaasConfig;
import de.gdata.vaas.exceptions.VaasAuthenticationException;
import de.gdata.vaas.exceptions.VaasClientException;
import de.gdata.vaas.exceptions.VaasConnectionClosedException;
import de.gdata.vaas.exceptions.VaasInvalidStateException;
import de.gdata.vaas.messages.Verdict;
import de.gdata.vaas.messages.VerdictRequest;
import de.gdata.vaas.messages.VerdictRequestAttributes;
import io.github.cdimascio.dotenv.Dotenv;

public class RealApiIntegrationTests {
    private static final Dotenv dotenv = getDotenv();
    private static Vaas vaas;

    private static Dotenv getDotenv() {
        var dotenv = Dotenv.configure()
            .ignoreIfMissing();

        Optional<File> envFile = findFile(".env");

        if (envFile.isPresent()) {
            var directory = envFile.get().getParent();
            dotenv.directory(directory);
        }

        return dotenv.load();
    }

    private static Optional<File> findFile(String name) {
        File currentDirectory = new File(System.getProperty("user.dir"));
        File file = new File(currentDirectory, name);

        while (!file.exists() && currentDirectory.getParentFile() != null) {
            currentDirectory = currentDirectory.getParentFile();
            file = new File(currentDirectory, name);
        }

        return file.exists() ? Optional.of(file) : Optional.empty();
    }

    @BeforeAll
    public static void setUpAll() throws URISyntaxException, InterruptedException, IOException, ExecutionException,
            TimeoutException, VaasAuthenticationException {
        System.out.println("VAAS_URL=" + getEnvironmentKey("VAAS_URL"));
        vaas = getVaasWithCredentials();
    }

    @AfterAll
    public static void tearDownAll() throws Exception {
        vaas.close();
    }

    @Test
    public void clientCredentialsGrantAuthenticatorGetToken() throws Exception {
        var clientId = getEnvironmentKey("CLIENT_ID");
        var clientSecret = getEnvironmentKey("CLIENT_SECRET");
        var tokenUrl = new URI(getEnvironmentKey("TOKEN_URL"));
        var authenticator = new ClientCredentialsGrantAuthenticator(clientId, clientSecret, tokenUrl);
        var token = authenticator.getToken();

        assertNotNull(token);
    }

    @Test
    public void resourceOwnerPasswordAuthenticatorGetToken() throws Exception {
        var clientId = getEnvironmentKey("VAAS_CLIENT_ID");
        var username = getEnvironmentKey("VAAS_USER_NAME");
        var password = getEnvironmentKey("VAAS_PASSWORD");
        var tokenUrl = new URI(getEnvironmentKey("TOKEN_URL"));
        var authenticator = new ResourceOwnerPasswordGrantAuthenticator(clientId, username, password, tokenUrl);
        var token = authenticator.getToken();

        assertNotNull(token);
    }

    @Test
    public void forSha256SingleMaliciousHash() throws Exception {
        var sha256 = new Sha256("ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2");

        var verdict = vaas.forSha256(sha256);

        assertEquals(Verdict.MALICIOUS, verdict.getVerdict());
        assertTrue("ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2"
                .equalsIgnoreCase(verdict.getSha256()));
    }

    @Test
    public void fromSha256SinglePupHash() throws Exception {
        var sha256 = new Sha256("d6f6c6b9fde37694e12b12009ad11ab9ec8dd0f193e7319c523933bdad8a50ad");

        var verdict = vaas.forSha256(sha256);

        assertEquals(Verdict.PUP, verdict.getVerdict());
        assertTrue("d6f6c6b9fde37694e12b12009ad11ab9ec8dd0f193e7319c523933bdad8a50ad"
                .equalsIgnoreCase(verdict.getSha256()));
    }

    @Test
    @Tag("ErrorLogProducer")
    public void illegalCredentials() throws Exception {
        var clientId = "NON_EXISTING_CLIENT_ID";
        var clientSecret = "A wizard is never late, Frodo Baggins. He arrives precisely when he means to!";
        var tokenUrl = new URI(getEnvironmentKey("TOKEN_URL"));
        var vaasUrl = getEnvironmentKey("VAAS_URL");
        var config = new VaasConfig(new URI(vaasUrl));
        var authenticator = new ClientCredentialsGrantAuthenticator(clientId, clientSecret, tokenUrl);
        try (var client = new Vaas(config, authenticator)) {
            assertThrows(Exception.class, client::connect);
        }
    }

    @Test
    @Tag("ErrorLogProducer")
    public void wrongTokenUsedToAuthenticateWebsocket() throws Exception {
        class MockAuthenticator implements IAuthenticator {

            @Override
            public String getToken() {
                return "arbitrary_wrong_token";
            }
        }

        var vaasUrl = getEnvironmentKey("VAAS_URL");
        var config = new VaasConfig(new URI(vaasUrl));
        var authenticator = new MockAuthenticator();

        try (var client = new Vaas(config, authenticator)) {
            assertThrows(VaasAuthenticationException.class, client::connect);
        }
    }

    @Test
    public void forSha256MultipleHashes() throws Exception {
        var sha256_1 = new Sha256("ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2");
        var sha256_2 = new Sha256("cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e");
        var sha256_3 = new Sha256("1f72c1111111111111f912e40b7323a0192a300b376186c10f6803dc5efe28df");

        var verdict_1 = vaas.forSha256(sha256_1);
        var verdict_2 = vaas.forSha256(sha256_2);
        var verdict_3 = vaas.forSha256(sha256_3);

        assertEquals(Verdict.MALICIOUS, verdict_1.getVerdict());
        assertEquals(Verdict.CLEAN, verdict_2.getVerdict());
        assertEquals(Verdict.UNKNOWN, verdict_3.getVerdict());

        assertTrue("ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2"
                .equalsIgnoreCase(verdict_1.getSha256()));
        assertTrue("cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e"
                .equalsIgnoreCase(verdict_2.getSha256()));
        assertTrue("1f72c1111111111111f912e40b7323a0192a300b376186c10f6803dc5efe28df"
                .equalsIgnoreCase(verdict_3.getSha256()));
    }

    @Test
    public void forSha256MultipleUnknownHash() throws Exception {
        var sha256_1 = new Sha256("110005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8");
        var sha256_2 = new Sha256("11000b68934493af2f5954593fe8127b9dda6d4b520e78265aa5875623b58c9c");
        var sha256_3 = new Sha256("11000f83e3120f79a21b7b395dd3dd6a9c31ce00857f78d7cf487476ca75fd1a");

        var verdict_1 = vaas.forSha256(sha256_1);
        var verdict_2 = vaas.forSha256(sha256_2);
        var verdict_3 = vaas.forSha256(sha256_3);

        assertEquals(Verdict.UNKNOWN, verdict_1.getVerdict());
        assertEquals(Verdict.UNKNOWN, verdict_2.getVerdict());
        assertEquals(Verdict.UNKNOWN, verdict_3.getVerdict());

        assertTrue("110005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8"
                .equalsIgnoreCase(verdict_1.getSha256()));
        assertTrue("11000b68934493af2f5954593fe8127b9dda6d4b520e78265aa5875623b58c9c"
                .equalsIgnoreCase(verdict_2.getSha256()));
        assertTrue("11000f83e3120f79a21b7b395dd3dd6a9c31ce00857f78d7cf487476ca75fd1a"
                .equalsIgnoreCase(verdict_3.getSha256()));
    }

    @Test
    public void forFileSingleMaliciousFile()
            throws Exception {
        var tmpFile = Sha256Test.writeEicar();

        var sha256 = new Sha256(tmpFile);
        var verdict = vaas.forFile(tmpFile);

        Files.deleteIfExists(tmpFile);
        assertEquals(Verdict.MALICIOUS, verdict.getVerdict());
        assertTrue(sha256.getValue().equalsIgnoreCase(verdict.getSha256()));
    }

    @Test
    public void forFileSingleMaliciousFileWithVerdictRequestAttributes()
            throws Exception {
        var tmpFile = Sha256Test.writeEicar();

        var sha256 = new Sha256(tmpFile);
        var verdict = vaas.forFile(tmpFile, new VerdictRequestAttributes() {
            {
                setTenantId("JavaSDK");
            }
        });

        Files.deleteIfExists(tmpFile);
        assertEquals(Verdict.MALICIOUS, verdict.getVerdict());
        assertTrue(sha256.getValue().equalsIgnoreCase(verdict.getSha256()));
    }

    @Test
    public void forFileSingleCleanFile()
            throws Exception {
        byte[] clean = { 0x65, 0x0a, 0x67, 0x0a, 0x65, 0x0a, 0x62, 0x0a };
        var tmpFile = Path.of(System.getProperty("java.io.tmpdir"), "clean.txt");
        Files.write(tmpFile, clean);

        var sha256 = new Sha256(tmpFile);
        var verdict = vaas.forFile(tmpFile);

        Files.deleteIfExists(tmpFile);
        assertEquals(Verdict.CLEAN, verdict.getVerdict());
        assertTrue(sha256.getValue().equalsIgnoreCase(verdict.getSha256()));
    }

    @Test
    public void forFileSingleUnknownFile()
            throws Exception {
        var unknown = getRandomString(50);
        var tmpFile = Path.of(System.getProperty("java.io.tmpdir"), "unknown.txt");
        Files.writeString(tmpFile, unknown);

        var sha256 = new Sha256(tmpFile);
        var verdict = vaas.forFile(tmpFile);

        Files.deleteIfExists(tmpFile);
        assert (verdict != null);
        assertEquals(Verdict.CLEAN, verdict.getVerdict());
        assertTrue(sha256.getValue().equalsIgnoreCase(verdict.getSha256()));
    }

    @Test
    public void forFileEmptyFile()
            throws Exception {
        byte[] clean = {};
        var tmpFile = Path.of(System.getProperty("java.io.tmpdir"), "empty.txt");

        Files.write(tmpFile, clean);

        var sha256 = new Sha256(tmpFile);
        var verdict = vaas.forFile(tmpFile);

        Files.deleteIfExists(tmpFile);
        assertEquals(Verdict.CLEAN, verdict.getVerdict());
        assertTrue(sha256.getValue().equalsIgnoreCase(verdict.getSha256()));
    }

    @Test
    @Disabled("Enable to test keep-alive")
    public void forFile_WorksWithBigSample() throws Exception {
        var verdict = vaas.forFile(Path.of("/home/vscode/big.zip"));
        assert (verdict != null);
        assertEquals(Verdict.MALICIOUS, verdict.getVerdict());
    }

    @Test
    @Disabled("Enable to test keep-alive")
    public void forSha256_WorksAfter40s() throws Exception {
        var sha256 = new Sha256("3A78F382E8E2968EC201B33178102E06DB72E4F2D1505E058A4613C1E977825C");
        var verdict = vaas.forSha256(sha256);
        assert (verdict != null);
        assertEquals(Verdict.CLEAN, verdict.getVerdict());
        Thread.sleep(40000);
        verdict = vaas.forSha256(sha256);
        assert (verdict != null);
        assertEquals(Verdict.CLEAN, verdict.getVerdict());
    }

    @Test
    public void forSha256_ThrowsConnectionClosed() throws Exception {
        try (var vaas = getVaasWithCredentials()) {
            vaas.disconnect();
            var sha256 = new Sha256("3A78F382E8E2968EC201B33178102E06DB72E4F2D1505E058A4613C1E977825C");
            assertThrows(VaasConnectionClosedException.class, () -> {
                vaas.forSha256(sha256);
            });
        }
    }

    @Test
    public void forSha256_VaasCloses() throws Exception {
        try (var vaas = getVaasWithCredentials()) {
            vaas.close();
            var sha256 = new Sha256("3A78F382E8E2968EC201B33178102E06DB72E4F2D1505E058A4613C1E977825C");
            assertThrows(VaasConnectionClosedException.class, () -> {
                vaas.forSha256(sha256);
            });
        }
    }

    @Test
    public void forSha256_ConnectHasntBeCalled() throws Exception {
        var clientId = getEnvironmentKey("CLIENT_ID");
        var clientSecret = getEnvironmentKey("CLIENT_SECRET");
        var tokenUrl = new URI(getEnvironmentKey("TOKEN_URL"));
        var vaasUrl = getEnvironmentKey("VAAS_URL");

        var authenticator = new ClientCredentialsGrantAuthenticator(clientId, clientSecret, tokenUrl);
        var config = new VaasConfig(new URI(vaasUrl));
        try (var vaas = new Vaas(config, authenticator)) {
            var sha256 = new Sha256("3A78F382E8E2968EC201B33178102E06DB72E4F2D1505E058A4613C1E977825C");
            assertThrows(VaasInvalidStateException.class, () -> {
                vaas.forSha256(sha256);
            });
        }
    }

    @Test
    public void forUrlMultipleMaliciousUrls() throws Exception {
        var url_1 = new URL("https://secure.eicar.org/eicar.com");
        var url_2 = new URL("https://secure.eicar.org/eicar.com.txt");
        var url_3 = new URL("https://secure.eicar.org/eicar_com.zip");

        var verdict_1 = vaas.forUrl(url_1);
        var verdict_2 = vaas.forUrl(url_2);
        var verdict_3 = vaas.forUrl(url_3);

        assertEquals(Verdict.MALICIOUS, verdict_1.getVerdict());
        assertEquals(Verdict.MALICIOUS, verdict_2.getVerdict());
        assertEquals(Verdict.MALICIOUS, verdict_3.getVerdict());
    }

    @Test
    @Tag("ErrorLogProducer")
    public void forUrl_WithoutAuthority_ThrowsURISyntaxException() throws Exception {
        var url_1 = new URL("https://");
        var e = assertThrows(URISyntaxException.class, () -> vaas.forUrl(url_1));
        assertEquals(
                "Expected scheme-specific part at index 6: https:",
                e.getMessage());
    }

    @Test
    public void forUrl_WithUrlNull_ThrowsNullPointerException() throws Exception {
        @SuppressWarnings("DataFlowIssue")
        var e = assertThrows(NullPointerException.class, () -> vaas.forUrl(null));
        assertEquals("url is marked non-null but is null", e.getMessage());
    }

    @Test
    @Tag("ErrorLogProducer")
    public void forUrl_WithUrlWithStatusCode4xx_ThrowsVaasClientException() throws Exception {
        var url_1 = new URL("https://gateway.production.vaas.gdatasecurity.de/swagger/nocontenthere");
        var e = assertThrows(VaasClientException.class, () -> vaas.forUrl(url_1));
        assertEquals(
                "Call failed with status code 404 (Not Found): GET https://gateway.production.vaas.gdatasecurity.de/swagger/nocontenthere",
                e.getMessage());
    }

    @Test
    @Disabled("Used for manual testing")
    public void forUrlInALoop() throws Exception {
        var url_1 = new URL("https://github.com/GDATASoftwareAG/vaas");

        while (true) {
            try {
                while (true) {
                    var verdict_1 = vaas.forUrl(url_1);
                    assertEquals(Verdict.CLEAN, verdict_1.getVerdict());
                    System.out.println(verdict_1.getVerdict());

                    DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss:SSS");
                    LocalDateTime now = LocalDateTime.now();
                    System.out.println(dtf.format(now));
                }

            } catch (ExecutionException e) {
                System.out.println(e);
            }

        }
    }

    @Test
    @Tag("ErrorLogProducer")
    public void forUrlMultipleCleanUrls() throws Exception {
        var url_1 = new URL("https://github.com/GDATASoftwareAG/vaas");
        var url_2 = new URL("https://github.com/GDATASoftwareAG/vaas");
        var url_3 = new URL("https://github.com/GDATASoftwareAG/vaas");

        var verdictRequestAttributes = new VerdictRequestAttributes();
        verdictRequestAttributes.setTenantId("GiveMeThatHashes");

        var verdict_1 = vaas.forUrl(url_1, verdictRequestAttributes);
        var verdict_2 = vaas.forUrl(url_2, verdictRequestAttributes);
        var verdict_3 = vaas.forUrl(url_3, verdictRequestAttributes);

        assertEquals(Verdict.CLEAN, verdict_1.getVerdict());
        assertEquals(Verdict.CLEAN, verdict_2.getVerdict());
        assertEquals(Verdict.CLEAN, verdict_3.getVerdict());
    }

    @Test
    public void serializationTest() {
        var sha256 = new Sha256("3A78F382E8E2968EC201B33178102E06DB72E4F2D1505E058A4613C1E977825C");
        var verdictRequestAttributes = new VerdictRequestAttributes();
        verdictRequestAttributes.setTenantId("Test");
        var verdictRequest = new VerdictRequest(sha256, "myid", verdictRequestAttributes);
        var json1 = verdictRequest.toJson();
        var json2 = verdictRequestAttributes.toJson();
        assertNotNull(json1, "");
        assertNotNull(json2, "");
    }

    @Test
    public void forSha256_WithSha256Null_ThrowsNullPointerException() throws Exception {
        @SuppressWarnings("DataFlowIssue")
        var e = assertThrows(NullPointerException.class, () -> vaas.forSha256(null));
        assertEquals("sha256 is marked non-null but is null", e.getMessage());
    }

    @Test
    public void forStream_WithCleanString_ReturnsCleanVerdict() throws Exception {
        var targetStream = new ByteArrayInputStream("I am clean".getBytes());
        var contentLength = targetStream.available();
        var verdict = vaas.forStream(targetStream, contentLength);

        assertEquals(Verdict.CLEAN, verdict.getVerdict());
    }

    @Test
    public void forStream_WithEicarString_ReturnsMaliciousVerdict() throws Exception {
        var targetStream = new ByteArrayInputStream(
                "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".getBytes());
        var contentLength = targetStream.available();
        var verdict = vaas.forStream(targetStream, contentLength);

        assertEquals(Verdict.MALICIOUS, verdict.getVerdict());
    }

    @Test
    public void forStream_WithCleanUrl_ReturnsCleanVerdict() throws Exception {
        var url = new URL("https://raw.githubusercontent.com/GDATASoftwareAG/vaas/main/Readme.md");
        var conn = url.openConnection();
        var inputStream = conn.getInputStream();
        var contentLength = conn.getContentLengthLong();

        var verdict = vaas.forStream(inputStream, contentLength);

        assertEquals(Verdict.CLEAN, verdict.getVerdict());
    }

    @Test
    public void forStream_WithEicarUrl_ReturnsMaliciousVerdict() throws Exception {
        var url = new URL("https://secure.eicar.org/eicar.com.txt");
        var conn = url.openConnection();
        var inputStream = conn.getInputStream();
        var contentLength = conn.getContentLengthLong();

        var verdict = vaas.forStream(inputStream, contentLength);

        assertEquals(Verdict.MALICIOUS, verdict.getVerdict());
    }

    private @NotNull String getRandomString(int size) {
        String AlphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvxyz0123456789";
        StringBuilder sb = new StringBuilder(size);

        for (int i = 0; i < size; i++) {
            int index = (int) (AlphaNumericString.length() * Math.random());
            sb.append(AlphaNumericString.charAt(index));
        }

        return sb.toString();
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
        var client = new Vaas(config, authenticator);
        client.connect();
        return client;
    }

    private static String getEnvironmentKey(String key) {
        var value = dotenv.get(key);
        if (value == null) {
            throw new IllegalArgumentException("Environment variable " + key + " must be set.");
        }
        return value;
    }

    @Test
    public void forStream_WithEicarFile_ReturnsMaliciousVerdictWithDetections() throws Exception {
        var url = new URL("https://secure.eicar.org/eicar.com.txt");
        var conn = url.openConnection();
        var inputStream = conn.getInputStream();
        var contentLength = conn.getContentLengthLong();

        var verdict = vaas.forStream(inputStream, contentLength);

        assertNotNull(verdict.getDetection());
        assertEquals(Verdict.MALICIOUS, verdict.getVerdict());
        assertEquals("EICAR virus test files", verdict.getFileType());
        assertEquals("text/plain", verdict.getMimeType());
    }

    @Test
    @Disabled("Runs endless. Monitor memory usage.")
    public void connect_RepeatedlyCalled_DoesntLeakMemory() throws Exception {
        var sha256 = new Sha256("ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2");

        while (true) {
            vaas.connect();
            var verdict = vaas.forSha256(sha256);

            assertEquals(Verdict.MALICIOUS, verdict.getVerdict());
        }
    }
}
