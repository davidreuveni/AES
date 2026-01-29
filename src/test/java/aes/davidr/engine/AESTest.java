package aes.davidr.engine;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

class AESTest {

    @Test
    void fips197_aes128_knownVector_encryptDecrypt() {
        byte[] key = hex("000102030405060708090A0B0C0D0E0F");
        byte[] pt  = hex("00112233445566778899AABBCCDDEEFF");
        byte[] exp = hex("69C4E0D86A7B0430D8CDB78070B4C55A");

        KeySchedule ks = new KeySchedule(key);

        
        assertArrayEquals(exp, AES.blockRun(true, pt.clone(), ks), "Encrypt KAT mismatch");

        
        assertArrayEquals(pt, AES.blockRun(false, exp.clone(), ks), "Decrypt KAT mismatch");
    }

    private static byte[] hex(String s) {
        s = s.replaceAll("\\s+", "");
        if ((s.length() & 1) != 0)
            throw new IllegalArgumentException("Odd hex length");
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(s.charAt(i * 2), 16);
            int lo = Character.digit(s.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0)
                throw new IllegalArgumentException("Bad hex");
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    @Test
    void testInvMixColumns() {
        byte[] s = new byte[] { 
                (byte) 0x04, (byte) 0x66, (byte) 0x81, (byte) 0xE5,
                (byte) 0xE0, (byte) 0xCB, (byte) 0x19, (byte) 0x9A,
                (byte) 0x48, (byte) 0xF8, (byte) 0xD3, (byte) 0x7A,
                (byte) 0x28, (byte) 0x06, (byte) 0x26, (byte) 0x4C
            };

        AES.invMixColumns(s, 0);

        byte[] ex = new byte[] { 
                (byte) 0xD4, (byte) 0xBF, (byte) 0x5D, (byte) 0x30,
                (byte) 0xE0, (byte) 0xB4, (byte) 0x52, (byte) 0xAE,
                (byte) 0xB8, (byte) 0x41, (byte) 0x11, (byte) 0xF1,
                (byte) 0x1E, (byte) 0x27, (byte) 0x98, (byte) 0xE5
            };

        assertArrayEquals(ex, s);
    }

    @Test
    void testInvShiftRows() {
        byte[] s = new byte[] {
            (byte) 0xD4, (byte) 0xBF, (byte) 0x5D, (byte) 0x30,
            (byte) 0xE0, (byte) 0xB4, (byte) 0x52, (byte) 0xAE,
            (byte) 0xB8, (byte) 0x41, (byte) 0x11, (byte) 0xF1,
            (byte) 0x1E, (byte) 0x27, (byte) 0x98, (byte) 0xE5
        };

        AES.invShiftRows(s, 0);

        byte[] ex = new byte[] { 
            (byte) 0xD4, (byte) 0x27, (byte) 0x11, (byte) 0xAE,
            (byte) 0xE0, (byte) 0xBF, (byte) 0x98, (byte) 0xF1,
            (byte) 0xB8, (byte) 0xB4, (byte) 0x5D, (byte) 0xE5,
            (byte) 0x1E, (byte) 0x41, (byte) 0x52, (byte) 0x30
        };

        assertArrayEquals(ex, s);
    }

    @Test
    void testInvSubBytes() {
        byte[] s = new byte[] { 
            (byte) 0xD4, (byte) 0x27, (byte) 0x11, (byte) 0xAE,
            (byte) 0xE0, (byte) 0xBF, (byte) 0x98, (byte) 0xF1,
            (byte) 0xB8, (byte) 0xB4, (byte) 0x5D, (byte) 0xE5,
            (byte) 0x1E, (byte) 0x41, (byte) 0x52, (byte) 0x30
        };

        AES.invSubBytes(s, 0);

        byte[] ex = new byte[] { 
            (byte) 0x19, (byte) 0x3D, (byte) 0xE3, (byte) 0xBE,
            (byte) 0xA0, (byte) 0xF4, (byte) 0xE2, (byte) 0x2B,
            (byte) 0x9A, (byte) 0xC6, (byte) 0x8D, (byte) 0x2A,
            (byte) 0xE9, (byte) 0xF8, (byte) 0x48, (byte) 0x08
        };

        assertArrayEquals(ex, s);
    }

    @Test
    void testMixColumns() {
        byte[] s = new byte[] {
            (byte) 0xD4, (byte) 0xBF, (byte) 0x5D, (byte) 0x30,
            (byte) 0xE0, (byte) 0xB4, (byte) 0x52, (byte) 0xAE,
            (byte) 0xB8, (byte) 0x41, (byte) 0x11, (byte) 0xF1,
            (byte) 0x1E, (byte) 0x27, (byte) 0x98, (byte) 0xE5
        };

        AES.mixColumns(s, 0);

        byte[] ex = new byte[] { 
            (byte) 0x04, (byte) 0x66, (byte) 0x81, (byte) 0xE5,
            (byte) 0xE0, (byte) 0xCB, (byte) 0x19, (byte) 0x9A,
            (byte) 0x48, (byte) 0xF8, (byte) 0xD3, (byte) 0x7A,
            (byte) 0x28, (byte) 0x06, (byte) 0x26, (byte) 0x4C
        };

        assertArrayEquals(ex, s);
    }

    @Test
    void testShiftRows() {
        byte[] s = new byte[] { 
            (byte) 0xD4, (byte) 0x27, (byte) 0x11, (byte) 0xAE,
            (byte) 0xE0, (byte) 0xBF, (byte) 0x98, (byte) 0xF1,
            (byte) 0xB8, (byte) 0xB4, (byte) 0x5D, (byte) 0xE5,
            (byte) 0x1E, (byte) 0x41, (byte) 0x52, (byte) 0x30
        };

        AES.shiftRows(s, 0);

        byte[] ex = new byte[] { 
            (byte) 0xD4, (byte) 0xBF, (byte) 0x5D, (byte) 0x30,
            (byte) 0xE0, (byte) 0xB4, (byte) 0x52, (byte) 0xAE,
            (byte) 0xB8, (byte) 0x41, (byte) 0x11, (byte) 0xF1,
            (byte) 0x1E, (byte) 0x27, (byte) 0x98, (byte) 0xE5
        };

        assertArrayEquals(ex, s);
    }

    @Test
    void testSubBytes() {
        byte[] s = new byte[] {
            (byte) 0x19, (byte) 0x3D, (byte) 0xE3, (byte) 0xBE,
            (byte) 0xA0, (byte) 0xF4, (byte) 0xE2, (byte) 0x2B,
            (byte) 0x9A, (byte) 0xC6, (byte) 0x8D, (byte) 0x2A,
            (byte) 0xE9, (byte) 0xF8, (byte) 0x48, (byte) 0x08
        };

        AES.subBytes(s, 0);

        byte[] ex = new byte[] { 
            (byte) 0xD4, (byte) 0x27, (byte) 0x11, (byte) 0xAE,
            (byte) 0xE0, (byte) 0xBF, (byte) 0x98, (byte) 0xF1,
            (byte) 0xB8, (byte) 0xB4, (byte) 0x5D, (byte) 0xE5,
            (byte) 0x1E, (byte) 0x41, (byte) 0x52, (byte) 0x30
        };

        assertArrayEquals(ex, s);
    }

    @Test
    void testXorRoundKey() {
        byte[] s = new byte[] { 
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F 
        },
                
        k = new byte[] { 
            0x0F, 0x0E, 0x0D, 0x0C,
            0x0B, 0x0A, 0x09, 0x08,
            0x07, 0x06, 0x05, 0x04,
            0x03, 0x02, 0x01, 0x00 
        };

        AES.xorRoundKey(s, k, 0);

        byte[] ex1 = new byte[] { 
            0x0F, 0x0F, 0x0F, 0x0F,
            0x0F, 0x0F, 0x0F, 0x0F,
            0x0F, 0x0F, 0x0F, 0x0F,
            0x0F, 0x0F, 0x0F, 0x0F
        };

        assertArrayEquals(ex1, s);

        AES.xorRoundKey(s, k, 0);

        byte[] ex2 = new byte[] { 
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F
        };

        assertArrayEquals(ex2, s);
    }

}
