package de.gdata.vaas;

import lombok.Getter;
import lombok.NonNull;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class Sha256 {
    @NonNull
    @Getter
    private String value;

    public Sha256(String sha256) {
        var lowerSha256 = sha256.toLowerCase();
        var pattern = Pattern.compile("^[A-Fa-f0-9]{64}$");
        var matcher = pattern.matcher(lowerSha256);

        if(!matcher.find()) {
            throw new IllegalArgumentException("Not a valid SHA256");
        }

        this.value = sha256;
    }

    public Sha256(Path file) throws IOException, NoSuchAlgorithmException {
        var bytes = Files.readAllBytes(file);
        var digest = MessageDigest.getInstance("SHA-256").digest(bytes);

        String sb = IntStream
                .range(0, digest.length)
                .mapToObj(i -> Integer.toString((digest[i] & 0xff) + 0x100, 16)
                        .substring(1)).collect(Collectors.joining());

        this.value = sb;
    }
}
