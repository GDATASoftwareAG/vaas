package de.gdata.test.unit;

import de.gdata.test.TestDotenv;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TestDotenvTest {
    @TempDir
    Path tempDir;

    @Test
    public void findEnvDirectory_FindsEnvInParentDirectory() throws Exception {
        var parentDirectory = Files.createDirectory(tempDir.resolve("parent"));
        var nestedDirectory = Files.createDirectories(parentDirectory.resolve("child/grandchild"));
        Files.writeString(parentDirectory.resolve(".env"), "CLIENT_ID=test-client\n");

        var envDirectory = TestDotenv.findEnvDirectory(nestedDirectory);

        assertTrue(envDirectory.isPresent());
        assertEquals(parentDirectory, envDirectory.get());
    }

    @Test
    public void findEnvDirectory_ReturnsEmptyWhenNoEnvExists() throws Exception {
        var nestedDirectory = Files.createDirectories(tempDir.resolve("child/grandchild"));

        var envDirectory = TestDotenv.findEnvDirectory(nestedDirectory);

        assertFalse(envDirectory.isPresent());
    }
}