package de.gdata.test.integration;

import de.gdata.vaas.Sha256;
import de.gdata.vaas.exceptions.VaasClientException;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.util.concurrent.locks.ReentrantLock;

public class SamplesFixture {
    private static final String CLEAN_SHA256 = "d24dc598b54a8eedb0a4b381fad68af956441dffa9c9d5d9ac81de73fcc0a089";
    private static final String EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
    private static final String PUP_SHA256 = "d6f6c6b9fde37694e12b12009ad11ab9ec8dd0f193e7319c523933bdad8a50ad";
    private URL cleanUrl;
    private URL eicarUrl;
    private URL pupUrl;
    private Path cleanSample;
    private Path eicarSample;
    private Path pupSample;

    private final ReentrantLock lock = new ReentrantLock();

    public SamplesFixture() {
        try {
            cleanUrl = URI.create("https://samples.develop.vaas.gdatasecurity.de/clean.txt").toURL();
            eicarUrl = URI.create("https://samples.develop.vaas.gdatasecurity.de/eicar.com.txt").toURL();
            pupUrl = URI.create("https://samples.develop.vaas.gdatasecurity.de/PotentiallyUnwanted.exe").toURL();
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    private Path downloadSample(URL url, String fileName, String expectedSha256) throws IOException, InterruptedException, VaasClientException {
        Path tmpDir = Path.of(System.getProperty("java.io.tmpdir"));
        Path targetFile = tmpDir.resolve(fileName);

        if (Files.exists(targetFile)) {
            String existingSha256 = new Sha256(targetFile).getValue();
            if (existingSha256.equals(expectedSha256)) {
                return targetFile;
            }
        }

        try (var inputStream = url.openStream()) {
            Files.copy(inputStream, targetFile, StandardCopyOption.REPLACE_EXISTING);
        }

        return targetFile;
    }

    public Path getCleanSample() throws IOException, InterruptedException, VaasClientException {
        lock.lock();
        try {
            if (cleanSample == null) {
                cleanSample = downloadSample(cleanUrl, "clean.txt", CLEAN_SHA256);
            }
            return cleanSample;
        } finally {
            lock.unlock();
        }
    }

    public Path getEicarSample() throws IOException, InterruptedException, VaasClientException {
        lock.lock();
        try {
            if (eicarSample == null) {
                eicarSample = downloadSample(eicarUrl, "eicar.com.txt", EICAR_SHA256);
            }
            return eicarSample;
        } finally {
            lock.unlock();
        }
    }

    public Path getPupSample() throws IOException, InterruptedException, VaasClientException {
        lock.lock();
        try {
            if (pupSample == null) {
                pupSample = downloadSample(pupUrl, "PotentiallyUnwanted.exe", PUP_SHA256);
            }
            return pupSample;
        } finally {
            lock.unlock();
        }
    }
}