package de.gdata.test.unit;

import de.gdata.vaas.Sha256;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class Sha256Test {
    @Test
    public void fromValidSha256() {
        assertEquals("00015b14c28c2951f6d628098ce6853e14300f1b7d6d985e18d508f9807f44d8", new Sha256("00015b14c28c2951f6d628098ce6853e14300f1b7d6d985e18d508f9807f44d8").getValue());
        assertEquals("000020f89134d831f48541b2d8ec39397bc99fccf4cc86a3861257dbe6d819d0", new Sha256("000020f89134d831f48541b2d8ec39397bc99fccf4cc86a3861257dbe6d819d0").getValue());
    }

    @Test
    public void fromInvalidSha256() {
        // Wrong characters
        assertThrows(IllegalArgumentException.class, () -> {
            new Sha256("x00020f89134d831f48541b2d8ec39397bc99fccf4cc86a3861257dbe6d819d0");
        });

        // Too short
        assertThrows(IllegalArgumentException.class, () -> {
            new Sha256("00020f89134d831f48541b2d8ec39397bc99fccf4cc86a3861257dbe6d819d0");
        });

        // Too long
        assertThrows(IllegalArgumentException.class, () -> {
            new Sha256("1000020f89134d831f48541b2d8ec39397bc99fccf4cc86a3861257dbe6d819d0");
        });
    }
}
