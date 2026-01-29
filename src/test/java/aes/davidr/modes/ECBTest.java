package aes.davidr.modes;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import aes.davidr.engine.AES;
import aes.davidr.engine.KeySchedule;

public class ECBTest {
    @Test
    void testEcbNormal() {

        byte[] key = hex("000102030405060708090A0B0C0D0E0F");
        byte[] pt = hex("00112233445566778899AABBCCDDEEFF");
        byte[] ct = hex("69C4E0D86A7B0430D8CDB78070B4C55A");
        byte[] tmp;

        KeySchedule ks = new KeySchedule(key);

        tmp = ECB.ecbProcessBlock(AES.ENCRYPT_MODE, pt.clone(), ks, 0);

        assertArrayEquals(ct, tmp, "ecb encryption mismatch");

        tmp = ECB.ecbProcessBlock(AES.DECRYPT_MODE, ct.clone(), ks, 0);

        assertArrayEquals(pt, tmp, "ecb encryption mismatch");
        

    }

    @Test
    void testEcbWrongInput() {
        byte[] key = hex("000102030405060708090A0B0C0D0E0F");
        byte[] pt = hex("00112233445566778899AABBCCDDEEFF");

        KeySchedule ks = new KeySchedule(key);

        assertThrows(IllegalArgumentException.class, () -> ECB.ecbProcessBlock(AES.DECRYPT_MODE, pt, ks, 7));
        assertThrows(IllegalArgumentException.class, () -> ECB.ecbProcessBlock(AES.DECRYPT_MODE, pt, ks, -7));
    }

    @Test
    void testEcbNullInput() {
        byte[] key = hex("000102030405060708090A0B0C0D0E0F");
        byte[] pt = hex("00112233445566778899AABBCCDDEEFF");
        byte[] ptNULL = null;

        KeySchedule ks = new KeySchedule(key);
        KeySchedule ksNULL = null;
        assertThrows(IllegalArgumentException.class, () -> ECB.ecbProcessBlock(AES.DECRYPT_MODE, pt, ksNULL, 0));
        assertThrows(IllegalArgumentException.class, () -> ECB.ecbProcessBlock(AES.DECRYPT_MODE, ptNULL, ks, 0));
    }

    @Test
    
    void testEcbPad() {

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

}
