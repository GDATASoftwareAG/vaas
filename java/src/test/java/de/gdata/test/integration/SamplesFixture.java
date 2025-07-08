package de.gdata.test.unit;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.concurrent.locks.ReentrantLock;

public class SamplesFixture {

    private static final String EICAR_URL = "https://samples.develop.vaas.gdatasecurity.de/eicar.com.txt";
    private static final String PUP_URL = "https://samples.develop.vaas.gdatasecurity.de/PotentiallyUnwanted.exe";

    private static final String EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
    private static final String PUP_SHA256 = "d6f6c6b9fde37694e12b12009ad11ab9ec8dd0f193e7319c523933bdad8a50ad";

    private Path eicarSample;
    private Path pupSample;

    private final ReentrantLock lock = new ReentrantLock();

    private static final HttpClient httpClient = HttpClient.newHttpClient();

    private Path downloadSample(String url, String fileName, String expectedSha256) throws IOException, InterruptedException {
        Path tmpDir = Path.of(System.getProperty("java.io.tmpdir"));
        Path targetFile = tmpDir.resolve(fileName);

        if (Files.exists(targetFile)) {
            String existingSha256 = new Sha256(targetFile).getValue();
            if (existingSha256.equals(expectedSha256)) {
                return targetFile;
            }
        }

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .build();

        HttpResponse<Path> response = httpClient.send(request, HttpResponse.BodyHandlers.ofFileDownload(tmpDir, fileName));

        if (response.statusCode() != 200) {
            throw new IOException("Failed to download sample from " + url);
        }

        Path downloadedFile = response.body();
        String downloadedSha256 = new Sha256(downloadedFile).getValue();
        if (!downloadedSha256.equals(expectedSha256)) {
            throw new IOException("SHA256 mismatch for " + fileName);
        }

        return downloadedFile;
    }

    public Path getEicarSample() throws IOException, InterruptedException {
        lock.lock();
        try {
            if (eicarSample == null) {
                eicarSample = downloadSample(EICAR_URL, "eicar.com.txt", EICAR_SHA256);
            }
            return eicarSample;
        } finally {
            lock.unlock();
        }
    }

    public Path getPupSample() throws IOException, InterruptedException {
        lock.lock();
        try {
            if (pupSample == null) {
                pupSample = downloadSample(PUP_URL, "PotentiallyUnwanted.exe", PUP_SHA256);
            }
            return pupSample;
        } finally {
            lock.unlock();
        }
    }
}