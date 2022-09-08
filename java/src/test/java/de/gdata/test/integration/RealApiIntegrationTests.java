package de.gdata.test.integration;

import de.gdata.vaas.CancellationTokenSource;
import de.gdata.vaas.Sha256;
import de.gdata.vaas.Vaas;
import de.gdata.vaas.WsConfig;
import de.gdata.vaas.messages.Verdict;
import io.github.cdimascio.dotenv.Dotenv;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import static org.testng.AssertJUnit.assertEquals;

public class RealApiIntegrationTests {
    @Test
    public void fromSha256SingleMaliciousHash() throws Exception {
        var vaas = this.getVaasWithCredentials();
        var sha256 = new Sha256("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8");
        var cts = new CancellationTokenSource(Duration.ofSeconds(10));

        var verdict = vaas.forSha256(sha256, cts);
        vaas.disconnect();

        assertEquals(Verdict.MALICIOUS, verdict.getVerdict());
    }

    @Test
    public void fromSha256SinglePupHash() throws Exception {
        var vaas = this.getVaasWithCredentials();
        var sha256 = new Sha256("d6f6c6b9fde37694e12b12009ad11ab9ec8dd0f193e7319c523933bdad8a50ad");
        var cts = new CancellationTokenSource(Duration.ofSeconds(10));

        var verdict = vaas.forSha256(sha256, cts);
        vaas.disconnect();

        assertEquals(Verdict.PUP, verdict.getVerdict());
    }

    @Test
    public void fromSha256MultipleMaliciousHash() throws Exception {
        var vaas = this.getVaasWithCredentials();
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
        var vaas = this.getVaasWithCredentials();
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
        var vaas = this.getVaasWithCredentials();
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
    public void fromSha256MultipleHashesWithDifferentVerdicts() throws Exception {
        var vaas = this.getVaasWithCredentials();
        var cts = new CancellationTokenSource(Duration.ofSeconds(10));
        var unknownHash = new Sha256("110005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8");
        var cleanHash = new Sha256("698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23");
        var pupHash = new Sha256("d6f6c6b9fde37694e12b12009ad11ab9ec8dd0f193e7319c523933bdad8a50ad");
        var maliciousHash = new Sha256("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8");

        var hashList = Arrays.asList(new Sha256[] { unknownHash, cleanHash, pupHash, maliciousHash });

        var verdicts = vaas.forSha256List(hashList, cts);
        vaas.disconnect();

        assertEquals(Verdict.UNKNOWN, verdicts.get(0).getVerdict());
        assertEquals(Verdict.CLEAN, verdicts.get(1).getVerdict());
        assertEquals(Verdict.PUP, verdicts.get(2).getVerdict());
        assertEquals(Verdict.MALICIOUS, verdicts.get(3).getVerdict());
    }

    @Test
    public void fromFileSingleMaliciousFile()
            throws Exception {
        var eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        var tmpFile = Path.of(System.getProperty("java.io.tmpdir"), "eicar.txt");
        Files.writeString(tmpFile, eicar);
        var vaas = this.getVaasWithCredentials();
        var cts = new CancellationTokenSource(Duration.ofSeconds(10));

        var verdict = vaas.forFile(tmpFile, cts);
        vaas.disconnect();

        Files.deleteIfExists(tmpFile);
        assertEquals(Verdict.MALICIOUS, verdict.getVerdict());
    }

    @Test
    public void fromFileSingleCleanFile()
            throws Exception {
        byte[] clean = { 0x65, 0x0a, 0x67, 0x0a, 0x65, 0x0a, 0x62, 0x0a };
        var tmpFile = Path.of(System.getProperty("java.io.tmpdir"), "clean.txt");
        Files.write(tmpFile, clean);
        var vaas = this.getVaasWithCredentials();
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
        var vaas = this.getVaasWithCredentials();
        var cts = new CancellationTokenSource(Duration.ofMinutes(10));

        var verdict = vaas.forFile(tmpFile, cts);
        vaas.disconnect();

        Files.deleteIfExists(tmpFile);
        assert (verdict != null);
        assertEquals(Verdict.CLEAN, verdict.getVerdict());
    }

    @Test
    @Disabled("Enable to test keep-alive")
    public void FromSha256_WorksAfter40s() throws Exception {
        var vaas = this.getVaasWithCredentials();
        var sha256 = new Sha256("698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23");
        var cts = new CancellationTokenSource(Duration.ofMinutes(10));
        var verdict = vaas.forSha256(sha256, cts);
        assert (verdict != null);
        assertEquals(Verdict.CLEAN, verdict.getVerdict());
        Thread.sleep(40000);
        verdict = vaas.forSha256(sha256, cts);
        assert (verdict != null);
        assertEquals(Verdict.CLEAN, verdict.getVerdict());
    }

    @Test
    public void fromFileListForDifferentVerdicts()
            throws Exception {

        var unknown = getRandomString(50);
        var unknownFile = Path.of(System.getProperty("java.io.tmpdir"), "unknown.txt");
        Files.writeString(unknownFile, unknown);

        byte[] clean = { 0x65, 0x0a, 0x67, 0x0a, 0x65, 0x0a, 0x62, 0x0a };
        var cleanFile = Path.of(System.getProperty("java.io.tmpdir"), "clean.txt");
        Files.write(cleanFile, clean);

        var eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        var maliciousFile = Path.of(System.getProperty("java.io.tmpdir"), "eicar.txt");
        Files.writeString(maliciousFile, eicar);

        var vaas = this.getVaasWithCredentials();
        var cts = new CancellationTokenSource(Duration.ofMinutes(10));

        var fileList = Arrays.asList(new Path[] {
                unknownFile,
                cleanFile,
                maliciousFile,
                maliciousFile,
                maliciousFile,
                cleanFile
        });

        var verdicts = vaas.forFileList(fileList, cts);
        vaas.disconnect();

        Files.deleteIfExists(unknownFile);
        Files.deleteIfExists(cleanFile);
        Files.deleteIfExists(maliciousFile);

        assert (verdicts.get(0) != null);
        assert (verdicts.get(1) != null);
        assert (verdicts.get(2) != null);
        assert (verdicts.get(3) != null);
        assert (verdicts.get(4) != null);
        assert (verdicts.get(5) != null);
        assertEquals(Verdict.CLEAN, verdicts.get(0).getVerdict());
        assertEquals(Verdict.CLEAN, verdicts.get(1).getVerdict());
        assertEquals(Verdict.MALICIOUS, verdicts.get(2).getVerdict());
        assertEquals(Verdict.MALICIOUS, verdicts.get(3).getVerdict());
        assertEquals(Verdict.MALICIOUS, verdicts.get(4).getVerdict());
        assertEquals(Verdict.CLEAN, verdicts.get(5).getVerdict());
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

    private Vaas getVaasWithCredentials() throws URISyntaxException, InterruptedException, IOException {
        var dotenv = Dotenv.configure()
                .ignoreIfMissing()
                .load();
        var clientId = dotenv.get("CLIENT_ID");
        var clientSecret = dotenv.get("CLIENT_SECRET");
        var tokenUrl = dotenv.get("TOKEN_URL");
        var vaasUrl = dotenv.get("VAAS_URL");
        var config = new WsConfig(clientId, clientSecret, new URI(tokenUrl), new URI(vaasUrl));
        var client = new Vaas(config);
        client.connect();
        return client;
    }

}