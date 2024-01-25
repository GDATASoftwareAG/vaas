package de.gdata.test.integration;

import de.gdata.vaas.*;
import de.gdata.vaas.exceptions.VaasAuthenticationException;
import de.gdata.vaas.exceptions.VaasClientException;
import de.gdata.vaas.exceptions.VaasConnectionClosedException;
import de.gdata.vaas.exceptions.VaasInvalidStateException;
import de.gdata.vaas.messages.VaasOptions;
import de.gdata.vaas.messages.Verdict;
import de.gdata.vaas.messages.VerdictRequest;
import de.gdata.vaas.messages.VerdictRequestAttributes;
import io.github.cdimascio.dotenv.Dotenv;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.testng.AssertJUnit.assertEquals;

public class RealApiIntegrationTests {
    @Test
    public void clientCredentialsGrantAuthenticatorGetToken() throws Exception {
        var dotenv = Dotenv.configure()
                .ignoreIfMissing()
                .load();
        var clientId = dotenv.get("CLIENT_ID");
        var clientSecret = dotenv.get("CLIENT_SECRET");
        var tokenUrl = new URI(dotenv.get("TOKEN_URL"));
        var authenticator = new ClientCredentialsGrantAuthenticator(clientId, clientSecret, tokenUrl);
        var token = authenticator.getToken();

        assertNotNull(token);
    }

    @Test
    public void resourceOwnerPasswordAuthenticatorGetToken() throws Exception {
        var dotenv = Dotenv.configure()
                .ignoreIfMissing()
                .load();
        var clientId = dotenv.get("VAAS_CLIENT_ID");
        var username = dotenv.get("VAAS_USER_NAME");
        var password = dotenv.get("VAAS_PASSWORD");
        var tokenUrl = new URI(dotenv.get("TOKEN_URL"));
        var authenticator = new ResourceOwnerPasswordGrantAuthenticator(clientId, username, password, tokenUrl);
        var token = authenticator.getToken();

        assertNotNull(token);
    }

    @Test
    public void fromSha256SingleMaliciousHash() throws Exception {
        var vaas = this.getVaasWithCredentials();
        var sha256 = new Sha256("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8");

        var verdict = vaas.forSha256(sha256);
        vaas.disconnect();

        assertEquals(Verdict.MALICIOUS, verdict.getVerdict());
        assertTrue("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8"
                .equalsIgnoreCase(verdict.getSha256()));
    }

    @Test
    public void fromSha256SinglePupHash() throws Exception {
        var vaas = this.getVaasWithCredentials();
        var sha256 = new Sha256("d6f6c6b9fde37694e12b12009ad11ab9ec8dd0f193e7319c523933bdad8a50ad");

        var verdict = vaas.forSha256(sha256);
        vaas.disconnect();

        assertEquals(Verdict.PUP, verdict.getVerdict());
        assertTrue("d6f6c6b9fde37694e12b12009ad11ab9ec8dd0f193e7319c523933bdad8a50ad"
                .equalsIgnoreCase(verdict.getSha256()));
    }

    @Test
    public void illegalCredentials() throws URISyntaxException {

        var dotenv = Dotenv.configure()
                .ignoreIfMissing()
                .load();
        var clientId = "NON_EXISTING_CLIENT_ID";
        var clientSecret = "A wizard is never late, Frodo Baggins. He arrives precisely when he means to!";
        var tokenUrl = new URI(dotenv.get("TOKEN_URL"));
        var vaasUrl = dotenv.get("VAAS_URL");
        var config = new VaasConfig(new URI(vaasUrl));
        var authenticator = new ClientCredentialsGrantAuthenticator(clientId, clientSecret, tokenUrl);
        var client = new Vaas(config, authenticator);
        assertThrows(Exception.class, client::connect);
    }

    @Test
    public void wrongTokenUsedToAuthenticateWebsocket() throws URISyntaxException {
        class MockAuthenticator implements IAuthenticator {

            @Override
            public String getToken() throws IOException, InterruptedException {
                return "arbitrary_wrong_token";
            }
        }

        var dotenv = Dotenv.configure()
                .ignoreIfMissing()
                .load();
        var tokenUrl = dotenv.get("TOKEN_URL");
        var vaasUrl = dotenv.get("VAAS_URL");
        var config = new VaasConfig(new URI(vaasUrl));
        var authenticator = new MockAuthenticator();

        var client = new Vaas(config, authenticator);

        assertThrows(VaasAuthenticationException.class, client::connect);
    }

    @Test
    public void fromSha256MultipleMaliciousHash() throws Exception {
        var vaas = this.getVaasWithCredentials();
        var sha256_1 = new Sha256("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8");
        var sha256_2 = new Sha256("00000b68934493af2f5954593fe8127b9dda6d4b520e78265aa5875623b58c9c");
        var sha256_3 = new Sha256("00000f83e3120f79a21b7b395dd3dd6a9c31ce00857f78d7cf487476ca75fd1a");

        var verdict_1 = vaas.forSha256(sha256_1);
        var verdict_2 = vaas.forSha256(sha256_2);
        var verdict_3 = vaas.forSha256(sha256_3);
        vaas.disconnect();

        assertEquals(Verdict.MALICIOUS, verdict_1.getVerdict());
        assertEquals(Verdict.MALICIOUS, verdict_2.getVerdict());
        assertEquals(Verdict.MALICIOUS, verdict_3.getVerdict());

        assertTrue("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8"
                .equalsIgnoreCase(verdict_1.getSha256()));
        assertTrue("00000b68934493af2f5954593fe8127b9dda6d4b520e78265aa5875623b58c9c"
                .equalsIgnoreCase(verdict_2.getSha256()));
        assertTrue("00000f83e3120f79a21b7b395dd3dd6a9c31ce00857f78d7cf487476ca75fd1a"
                .equalsIgnoreCase(verdict_3.getSha256()));
    }

    @Test
    public void fromSha256MultipleCleanHash() throws Exception {
        var vaas = this.getVaasWithCredentials();
        var sha256_1 = new Sha256("3A78F382E8E2968EC201B33178102E06DB72E4F2D1505E058A4613C1E977825C");
        var sha256_2 = new Sha256("1AFAFE9157FF5670BBEC8CE622F45D1CE51B3EE77B7348D3A237E232F06C5391");
        var sha256_3 = new Sha256("4447FAACEFABA8F040822101E2A4103031660DE9139E70ECFF9AA3A89455A783");

        var verdict_1 = vaas.forSha256(sha256_1);
        var verdict_2 = vaas.forSha256(sha256_2);
        var verdict_3 = vaas.forSha256(sha256_3);
        vaas.disconnect();

        assertEquals(Verdict.CLEAN, verdict_1.getVerdict());
        assertEquals(Verdict.CLEAN, verdict_2.getVerdict());
        assertEquals(Verdict.CLEAN, verdict_3.getVerdict());

        assertTrue("3A78F382E8E2968EC201B33178102E06DB72E4F2D1505E058A4613C1E977825C"
                .equalsIgnoreCase(verdict_1.getSha256()));
        assertTrue("1AFAFE9157FF5670BBEC8CE622F45D1CE51B3EE77B7348D3A237E232F06C5391"
                .equalsIgnoreCase(verdict_2.getSha256()));
        assertTrue("4447FAACEFABA8F040822101E2A4103031660DE9139E70ECFF9AA3A89455A783"
                .equalsIgnoreCase(verdict_3.getSha256()));
    }

    @Test
    public void fromSha256MultipleUnknownHash() throws Exception {
        var vaas = this.getVaasWithCredentials();
        var sha256_1 = new Sha256("110005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8");
        var sha256_2 = new Sha256("11000b68934493af2f5954593fe8127b9dda6d4b520e78265aa5875623b58c9c");
        var sha256_3 = new Sha256("11000f83e3120f79a21b7b395dd3dd6a9c31ce00857f78d7cf487476ca75fd1a");

        var verdict_1 = vaas.forSha256(sha256_1);
        var verdict_2 = vaas.forSha256(sha256_2);
        var verdict_3 = vaas.forSha256(sha256_3);
        vaas.disconnect();

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
    public void fromFileSingleMaliciousFile()
            throws Exception {
        var eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        var tmpFile = Path.of(System.getProperty("java.io.tmpdir"), "eicar.txt");
        Files.writeString(tmpFile, eicar);
        var vaas = this.getVaasWithCredentials();

        var sha256 = new Sha256(tmpFile);
        var verdict = vaas.forFile(tmpFile);
        vaas.disconnect();

        Files.deleteIfExists(tmpFile);
        assertEquals(Verdict.MALICIOUS, verdict.getVerdict());
        assertTrue(sha256.getValue().equalsIgnoreCase(verdict.getSha256()));
    }

    @Test
    public void fromFileSingleMaliciousFileWithVerdictRequestAttributes()
            throws Exception {
        var eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        var tmpFile = Path.of(System.getProperty("java.io.tmpdir"), "eicar.txt");
        Files.writeString(tmpFile, eicar);
        var vaas = this.getVaasWithCredentials();

        var sha256 = new Sha256(tmpFile);
        var verdict = vaas.forFile(tmpFile, new VerdictRequestAttributes() {
            {
                setTenantId("JavaSDK");
            }
        });
        vaas.disconnect();

        Files.deleteIfExists(tmpFile);
        assertEquals(Verdict.MALICIOUS, verdict.getVerdict());
        assertTrue(sha256.getValue().equalsIgnoreCase(verdict.getSha256()));
    }

    @Test
    public void fromFileSingleCleanFile()
            throws Exception {
        byte[] clean = { 0x65, 0x0a, 0x67, 0x0a, 0x65, 0x0a, 0x62, 0x0a };
        var tmpFile = Path.of(System.getProperty("java.io.tmpdir"), "clean.txt");
        Files.write(tmpFile, clean);
        var vaas = this.getVaasWithCredentials();

        var sha256 = new Sha256(tmpFile);
        var verdict = vaas.forFile(tmpFile);
        vaas.disconnect();

        Files.deleteIfExists(tmpFile);
        assertEquals(Verdict.CLEAN, verdict.getVerdict());
        assertTrue(sha256.getValue().equalsIgnoreCase(verdict.getSha256()));
    }

    @Test
    public void fromFileSingleUnknownFile()
            throws Exception {
        var unknown = getRandomString(50);
        var tmpFile = Path.of(System.getProperty("java.io.tmpdir"), "unknown.txt");
        Files.writeString(tmpFile, unknown);
        var vaas = this.getVaasWithCredentials();

        var sha256 = new Sha256(tmpFile);
        var verdict = vaas.forFile(tmpFile);
        vaas.disconnect();

        Files.deleteIfExists(tmpFile);
        assert (verdict != null);
        assertEquals(Verdict.CLEAN, verdict.getVerdict());
        assertTrue(sha256.getValue().equalsIgnoreCase(verdict.getSha256()));
    }

    @Test
    public void fromFileEmptyFile()
            throws Exception {
        byte[] clean = {};
        var tmpFile = Path.of(System.getProperty("java.io.tmpdir"), "empty.txt");
        Files.write(tmpFile, clean);
        var vaas = this.getVaasWithCredentials();

        var sha256 = new Sha256(tmpFile);
        var verdict = vaas.forFile(tmpFile);
        vaas.disconnect();

        Files.deleteIfExists(tmpFile);
        assertEquals(Verdict.CLEAN, verdict.getVerdict());
        assertTrue(sha256.getValue().equalsIgnoreCase(verdict.getSha256()));
    }

    @Test
    @Disabled("Enable to test keep-alive")
    public void fromFile_WorksWithBigSample() throws Exception {
        var vaas = this.getVaasWithCredentials();
        var verdict = vaas.forFile(Path.of("/home/vscode/big.zip"));
        assert (verdict != null);
        assertEquals(Verdict.MALICIOUS, verdict.getVerdict());
    }

    @Test
    @Disabled("Enable to test keep-alive")
    public void fromSha256_WorksAfter40s() throws Exception {
        var vaas = this.getVaasWithCredentials();
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
    public void fromSha256_ThrowsConnectionClosed() throws Exception {
        var vaas = this.getVaasWithCredentials();
        vaas.disconnect();
        var sha256 = new Sha256("3A78F382E8E2968EC201B33178102E06DB72E4F2D1505E058A4613C1E977825C");
        assertThrows(VaasConnectionClosedException.class, () -> {
            vaas.forSha256(sha256);
        });
    }

    @Test
    public void fromSha256_ConnectHasntBeCalled() throws Exception {
        var dotenv = Dotenv.configure()
                .ignoreIfMissing()
                .load();
        var clientId = dotenv.get("CLIENT_ID");
        var clientSecret = dotenv.get("CLIENT_SECRET");
        var tokenUrl = new URI(dotenv.get("TOKEN_URL"));
        var vaasUrl = dotenv.get("VAAS_URL");

        var authenticator = new ClientCredentialsGrantAuthenticator(clientId, clientSecret, tokenUrl);
        var config = new VaasConfig(new URI(vaasUrl));
        var vaas = new Vaas(config, authenticator);
        var sha256 = new Sha256("3A78F382E8E2968EC201B33178102E06DB72E4F2D1505E058A4613C1E977825C");
        assertThrows(VaasInvalidStateException.class, () -> {
            vaas.forSha256(sha256);
        });
    }

    @Test
    public void fromUrlMultipleMaliciousUrls() throws Exception {
        var vaas = this.getVaasWithCredentials();
        var url_1 = new URL("https://secure.eicar.org/eicar.com");
        var url_2 = new URL("https://secure.eicar.org/eicar.com.txt");
        var url_3 = new URL("https://secure.eicar.org/eicar_com.zip");

        var verdict_1 = vaas.forUrl(url_1);
        var verdict_2 = vaas.forUrl(url_2);
        var verdict_3 = vaas.forUrl(url_3);
        vaas.disconnect();

        assertEquals(Verdict.MALICIOUS, verdict_1.getVerdict());
        assertEquals(Verdict.MALICIOUS, verdict_2.getVerdict());
        assertEquals(Verdict.MALICIOUS, verdict_3.getVerdict());
    }

    @Test
    public void forUrl_WithInvalidUrl_ThrowsVaasClientException() throws Exception {
        var vaas = this.getVaasWithCredentials();
        var url_1 = new URL("https://");
        var e = assertThrows(VaasClientException.class, () -> vaas.forUrl(url_1));
        assertEquals("Call failed. An invalid request URI was provided. Either the request URI must be an absolute URI or BaseAddress must be set: GET https:", e.getMessage());
    }

    @Test
    public void forUrl_WithUrlNull_ThrowsNullPointerException() throws Exception {
        var vaas = this.getVaasWithCredentials();
        @SuppressWarnings("DataFlowIssue") var e = assertThrows(NullPointerException.class, () -> vaas.forUrl(null));
        assertEquals("url is marked non-null but is null", e.getMessage());
    }

    @Test
    public void forUrl_WithUrlWithStatusCode4xx_ThrowsVaasClientException() throws Exception {
        var vaas = this.getVaasWithCredentials();
        var url_1 = new URL("https://upload.production.vaas.gdatasecurity.de/nocontenthere");
        var e = assertThrows(VaasClientException.class, () -> vaas.forUrl(url_1));
        assertEquals("Call failed with status code 404 (Not Found): GET https://upload.production.vaas.gdatasecurity.de/nocontenthere", e.getMessage());
    }

    @Test
    @Disabled("Used for manual testing")
    public void fromUrlInALoop() throws Exception {
        var url_1 = new URL("https://github.com/GDATASoftwareAG/vaas");

        while (true) {
            try {
                var vaas = this.getVaasWithCredentials();
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
    public void fromUrlMultipleCleanUrls() throws Exception {
        var vaas = this.getVaasWithCredentials();
        var url_1 = new URL("https://github.com/GDATASoftwareAG/vaas");
        var url_2 = new URL("https://github.com/GDATASoftwareAG/vaas");
        var url_3 = new URL("https://github.com/GDATASoftwareAG/vaas");

        var verdictRequestAttributes = new VerdictRequestAttributes();
        verdictRequestAttributes.setTenantId("GiveMeThatHashes");

        var verdict_1 = vaas.forUrl(url_1, verdictRequestAttributes);
        var verdict_2 = vaas.forUrl(url_2, verdictRequestAttributes);
        var verdict_3 = vaas.forUrl(url_3, verdictRequestAttributes);
        vaas.disconnect();

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
        var vaas = this.getVaasWithCredentials();
        @SuppressWarnings("DataFlowIssue") var e = assertThrows(NullPointerException.class, () -> vaas.forSha256(null));
        assertEquals("sha256 is marked non-null but is null", e.getMessage());
    }

    @Test
    public void forInputStream_WithCleanString_ReturnsCleanVerdict() throws Exception {
        var vaas = this.getVaasWithCredentials();
        InputStream targetStream = new ByteArrayInputStream("I am clean".getBytes());
        var verdict = vaas.forInputStream(targetStream);

        assertEquals("Clean", verdict.getVerdict());
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

    private Vaas getVaasWithCredentials()
            throws URISyntaxException, InterruptedException, IOException, ExecutionException, TimeoutException,
            VaasAuthenticationException {
        var dotenv = Dotenv.configure()
                .ignoreIfMissing()
                .load();
        var clientId = dotenv.get("CLIENT_ID");
        var clientSecret = dotenv.get("CLIENT_SECRET");
        var tokenUrl = new URI(dotenv.get("TOKEN_URL"));
        var vaasUrl = dotenv.get("VAAS_URL");

        var authenticator = new ClientCredentialsGrantAuthenticator(clientId, clientSecret, tokenUrl);
        var config = new VaasConfig(new URI(vaasUrl));
        var client = new Vaas(config, authenticator);
        client.connect();
        return client;
    }
}
