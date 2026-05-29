package de.gdata.test;

import io.github.cdimascio.dotenv.Dotenv;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;

public final class TestDotenv {
    private static final String ENV_FILENAME = ".env";

    private TestDotenv() {
    }

    public static Dotenv load() {
        return load(Paths.get("").toAbsolutePath());
    }

    public static Dotenv load(Path startDirectory) {
        var envDirectory = findEnvDirectory(startDirectory);
        var dotenv = Dotenv.configure()
                .ignoreIfMissing();

        envDirectory.ifPresent(path -> dotenv.directory(path.toString()).filename(ENV_FILENAME));

        return dotenv.load();
    }

    public static Optional<Path> findEnvDirectory(Path startDirectory) {
        var currentDirectory = startDirectory.toAbsolutePath().normalize();

        while (currentDirectory != null) {
            if (Files.isRegularFile(currentDirectory.resolve(ENV_FILENAME))) {
                return Optional.of(currentDirectory);
            }
            currentDirectory = currentDirectory.getParent();
        }

        return Optional.empty();
    }
}