package de.gdata.vaas;

import lombok.Getter;
import lombok.NonNull;
import org.jetbrains.annotations.NotNull;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Pattern;

@Getter
public class Sha256 {
    private static final Pattern pattern = Pattern.compile("^[A-Fa-f0-9]{64}$");

    @NonNull
    private final String value;

    public Sha256(@NotNull String sha256) {
        var matcher = pattern.matcher(sha256);

        if (!matcher.find()) {
            throw new IllegalArgumentException("Not a valid SHA256");
        }

        this.value = sha256;
    }

    public Sha256(Path file) throws IOException, NoSuchAlgorithmException {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        try (FileInputStream fileInputStream = new FileInputStream(file.toString());
            DigestInputStream digestInputStream = new DigestInputStream(fileInputStream, sha256)) {
            
            byte[] buffer = new byte[8192];
            while (digestInputStream.read(buffer) != -1) {
                // Read file in chunks and update the digest
            }
            
            byte[] digest = sha256.digest();
            StringBuilder hexString = new StringBuilder();
            for (byte b : digest) {
                hexString.append(String.format("%02x", b));
            }
            this.value = hexString.toString();
        }
    }
}
