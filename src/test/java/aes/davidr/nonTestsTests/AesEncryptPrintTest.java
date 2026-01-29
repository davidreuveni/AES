package aes.davidr.nonTestsTests;

import aes.davidr.engine.KeySchedule;
import aes.davidr.modes.ECB;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AesEncryptPrintTest {

    public static void encryptStringAndPrint() {
        // --- input ---
        String plaintext = "Hello from JUnit!";
        byte[] pt = plaintext.getBytes(StandardCharsets.UTF_8);

        // --- key (example 16 bytes = AES-128) ---
        byte[] key = new byte[] {
                0x00,0x01,0x02,0x03,
                0x04,0x05,0x06,0x07,
                0x08,0x09,0x0A,0x0B,
                0x0C,0x0D,0x0E,0x0F
        };

        // --- your AES calls (adjust these lines to match your project) ---
        KeySchedule ks = new KeySchedule(key);
        byte[] ct = ECB.ecbCryptBytes(true, pt, ks);  // or AES.encrypt(...), etc.
        

        // --- print results ---
        System.out.println("Plaintext: " + plaintext);
        System.out.println("Ciphertext (hex): " + toHex(ct));
        System.out.println("Ciphertext (base64): " + Base64.getEncoder().encodeToString(ct));
    }

    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02X", x & 0xFF));
        return sb.toString();
    }

    public static void main(String[] args) {
        encryptStringAndPrint();
    }
}
