package aes.davidr.engine;

import static org.junit.Assert.assertThrows;

import org.junit.jupiter.api.Test;

public class KeyScheduleTest {
    @Test
    void testKeyScheduleInvalidLength() {
        byte[] data = {
                0x00, 0x01, 0x02, 0x03,
                0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B,
                0x0C, 0x0D
        };
        byte[] nul = null;

        assertThrows(IllegalArgumentException.class, () -> {new KeySchedule(data);});
        assertThrows(IllegalArgumentException.class, () -> {new KeySchedule(nul);});
    }
    @Test
    void testGetNr() {
        byte[] key = {
                0x00, 0x01, 0x02, 0x03,
                0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B,
                0x0C, 0x0D, 0x0D, 0x0D,
                0x00, 0x01, 0x02, 0x03,
                0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B,
                0x0C, 0x0D, 0x0D, 0x0D
        };
        KeySchedule ks = new KeySchedule(key);
        assertThrows(IllegalArgumentException.class, () -> { ks.roundKey(50);});

    }

    @Test
    void testKeySchedule() {
        KeySchedule ks1 = new KeySchedule("aaaa", KeySchedule.AES_256);
        KeySchedule ks2 = new KeySchedule("aaaa");
    }
}
