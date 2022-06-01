package de.gdata.test.integration;

import de.gdata.vaas.CancellationTokenSource;
import de.gdata.vaas.Sha256;
import de.gdata.vaas.Vaas;
import de.gdata.vaas.WsConfig;
import de.gdata.vaas.messages.Verdict;
import io.github.cdimascio.dotenv.Dotenv;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.testng.annotations.Ignore;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

import static org.testng.AssertJUnit.assertEquals;

public class RealApiIntegrationTests {
    @Test
    public void fromSha256SingleMaliciousHash() throws Exception {
        var vaas = this.getVaas();
        var sha256 = new Sha256("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8");
        var cts = new CancellationTokenSource(Duration.ofSeconds(10));

        var verdict = vaas.forSha256(sha256, cts);
        vaas.disconnect();

        assertEquals(Verdict.MALICIOUS, verdict.getVerdict());
    }

    @Test
    public void fromSha256MultipleMaliciousHash() throws Exception {
        var vaas = this.getVaas();
        var cts = new CancellationTokenSource(Duration.ofSeconds(10));
        var sha256_1 = new Sha256("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8");
        var sha256_2 = new Sha256("00000b68934493af2f5954593fe8127b9dda6d4b520e78265aa5875623b58c9c");
        var sha256_3 = new Sha256("00000f83e3120f79a21b7b395dd3dd6a9c31ce00857f78d7cf487476ca75fd1a");

        var verdict_1 = vaas.forSha256(sha256_1, cts);
        var verdict_2 = vaas.forSha256(sha256_2, cts);
        var verdict_3 = vaas.forSha256(sha256_3, cts);
        vaas.disconnect();

        assertEquals(Verdict.MALICIOUS, verdict_1.getVerdict());
        assertEquals(Verdict.MALICIOUS, verdict_2.getVerdict());
        assertEquals(Verdict.MALICIOUS, verdict_3.getVerdict());
    }

    @Test
    public void fromSha256MultipleCleanHash() throws Exception {
        var vaas = this.getVaas();
        var cts = new CancellationTokenSource(Duration.ofSeconds(10));
        var sha256_1 = new Sha256("698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23");
        var sha256_2 = new Sha256("1AFAFE9157FF5670BBEC8CE622F45D1CE51B3EE77B7348D3A237E232F06C5391");
        var sha256_3 = new Sha256("4447FAACEFABA8F040822101E2A4103031660DE9139E70ECFF9AA3A89455A783");

        var verdict_1 = vaas.forSha256(sha256_1, cts);
        var verdict_2 = vaas.forSha256(sha256_2, cts);
        var verdict_3 = vaas.forSha256(sha256_3, cts);
        vaas.disconnect();

        assertEquals(Verdict.CLEAN, verdict_1.getVerdict());
        assertEquals(Verdict.CLEAN, verdict_2.getVerdict());
        assertEquals(Verdict.CLEAN, verdict_3.getVerdict());
    }

    @Test
    public void fromSha256MultipleUnknownHash() throws Exception {
        var vaas = this.getVaas();
        var cts = new CancellationTokenSource(Duration.ofSeconds(10));
        var sha256_1 = new Sha256("110005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8");
        var sha256_2 = new Sha256("11000b68934493af2f5954593fe8127b9dda6d4b520e78265aa5875623b58c9c");
        var sha256_3 = new Sha256("11000f83e3120f79a21b7b395dd3dd6a9c31ce00857f78d7cf487476ca75fd1a");

        var verdict_1 = vaas.forSha256(sha256_1, cts);
        var verdict_2 = vaas.forSha256(sha256_2, cts);
        var verdict_3 = vaas.forSha256(sha256_3, cts);
        vaas.disconnect();

        assertEquals(Verdict.UNKNOWN, verdict_1.getVerdict());
        assertEquals(Verdict.UNKNOWN, verdict_2.getVerdict());
        assertEquals(Verdict.UNKNOWN, verdict_3.getVerdict());
    }

    @Test
    public void fromFileSingleMaliciousFile()
            throws Exception {
        var eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        var tmpFile = Path.of(System.getProperty("java.io.tmpdir"), "eicar.txt");
        Files.writeString(tmpFile, eicar);
        var vaas = this.getVaas();
        var cts = new CancellationTokenSource(Duration.ofSeconds(10));

        var verdict = vaas.forFile(tmpFile, cts);
        vaas.disconnect();

        Files.deleteIfExists(tmpFile);
        assertEquals(Verdict.MALICIOUS, verdict.getVerdict());
    }

    @Test
    public void fromFileSingleCleanFile()
            throws Exception {
        byte[] clean = {0x65, 0x0a, 0x67, 0x0a, 0x65, 0x0a, 0x62, 0x0a};
        var tmpFile = Path.of(System.getProperty("java.io.tmpdir"), "clean.txt");
        Files.write(tmpFile, clean);
        var vaas = this.getVaas();
        var cts = new CancellationTokenSource(Duration.ofSeconds(10));

        var verdict = vaas.forFile(tmpFile, cts);
        vaas.disconnect();

        Files.deleteIfExists(tmpFile);
        assertEquals(Verdict.CLEAN, verdict.getVerdict());
    }

    @Test
    public void fromFileSingleUnknownFile()
            throws Exception {
        var unknown = getRandomString(50);
        var tmpFile = Path.of(System.getProperty("java.io.tmpdir"), "unknown.txt");
        Files.writeString(tmpFile, unknown);
        var vaas = this.getVaas();
        var cts = new CancellationTokenSource(Duration.ofMinutes(10));

        var verdict = vaas.forFile(tmpFile, cts);
        vaas.disconnect();

        Files.deleteIfExists(tmpFile);
        assert (verdict != null);
        assertEquals(Verdict.CLEAN, verdict.getVerdict());
    }

    @Ignore
    @Test
    public void fromFileSingleCleanFileWithCredentials()
            throws Exception {
        byte[] clean = {0x65, 0x0a, 0x67, 0x0a, 0x65, 0x0a, 0x62, 0x0a};
        var tmpFile = Path.of(System.getProperty("java.io.tmpdir"), "clean.txt");
        Files.write(tmpFile, clean);
        var stagingVaas = this.getVaasWithCredentials();
        var cts = new CancellationTokenSource(Duration.ofSeconds(10));

        var verdict = stagingVaas.forFile(tmpFile, cts);
        stagingVaas.disconnect();

        Files.deleteIfExists(tmpFile);
        assertEquals(Verdict.CLEAN, verdict.getVerdict());
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

    @org.jetbrains.annotations.NotNull
    private Vaas getVaas() throws URISyntaxException, InterruptedException, IOException {
        var dotenv = Dotenv.configure()
            .ignoreIfMissing()
            .load();
        var token = dotenv.get("VAAS_TOKEN");

        var config = new WsConfig(token);
        var client = new Vaas(config);
        client.connect();
        return client;
    }

    private Vaas getVaasWithCredentials() throws URISyntaxException, InterruptedException, IOException {
        var dotenv = Dotenv.configure()
                .ignoreIfMissing()
                .load();
        var clientId = dotenv.get("CLIENT_ID");
        var clientSecret = dotenv.get("CLIENT_SECRET");
        var config = new WsConfig(clientId,clientSecret);
        var client = new Vaas(config);
        client.connect();
        return client;
    }

}