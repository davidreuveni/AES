package aes.davidr.fileCrypto;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

public class HMACTests {

    @TempDir
    Path tempDir;

    private static final byte[] KEY1 = new byte[] {
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F
    };

    private static final byte[] KEY2 = new byte[] {
            0x10, 0x11, 0x12, 0x13,
            0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F
    };

    // ---------------- helpers ----------------

    private Path writeRandomFile(String name, int bytes) throws Exception {
        Path p = tempDir.resolve(name);
        byte[] data = new byte[bytes];
        new SecureRandom().nextBytes(data);
        Files.write(p, data);
        return p;
    }

    private static void flipOneByte(Path p, long index) throws Exception {
        byte[] b = Files.readAllBytes(p);
        int i = (int) index;
        b[i] ^= 0x01;
        Files.write(p, b);
    }

    // ============================================================
    // 1) Happy path: encrypt->decrypt matches original
    // ============================================================

    @Test
    void encryptThenDecrypt_roundTrip_ok() throws Exception {
        Path plain = writeRandomFile("plain.bin", 2_000_000); // ~2MB
        Path enc = tempDir.resolve("plain.bin.enc");
        Path dec = tempDir.resolve("plain.bin.dec");

        HMAC.processFile(HMAC.ENCRYPT_MODE, plain.toFile(), enc.toFile(), KEY1);
        HMAC.processFile(HMAC.DECRYPT_MODE, enc.toFile(), dec.toFile(), KEY1);

        assertArrayEquals(Files.readAllBytes(plain), Files.readAllBytes(dec));
    }

    // ============================================================
    // 2) Wrong key: decrypt must fail (integrity check)
    // ============================================================

    @Test
    void decrypt_wrongKey_rejected() throws Exception {
        Path plain = writeRandomFile("plain.bin", 500_000);
        Path enc = tempDir.resolve("plain.bin.enc");
        Path dec = tempDir.resolve("plain.bin.dec");

        HMAC.processFile(HMAC.ENCRYPT_MODE, plain.toFile(), enc.toFile(), KEY1);

        assertThrows(Exception.class, () -> HMAC.processFile(HMAC.DECRYPT_MODE, enc.toFile(), dec.toFile(), KEY2));
    }

    // ============================================================
    // 3) Tamper: flip a byte in ciphertext (should fail)
    // ============================================================

    @Test
    void tamper_ciphertextByte_rejected() throws Exception {
        Path plain = writeRandomFile("plain.bin", 1_000_000);
        Path enc = tempDir.resolve("plain.bin.enc");
        Path dec = tempDir.resolve("plain.bin.dec");

        HMAC.processFile(HMAC.ENCRYPT_MODE, plain.toFile(), enc.toFile(), KEY1);

        long size = Files.size(enc);
        assertTrue(size > 200, "encrypted file unexpectedly small");

        // Flip a byte near the end (likely ciphertext area)
        flipOneByte(enc, Math.min(size - 1, 200));

        assertThrows(Exception.class, () -> HMAC.processFile(HMAC.DECRYPT_MODE, enc.toFile(), dec.toFile(), KEY1));
    }

    // ============================================================
    // 4) Tamper: flip a byte in header (should fail)
    // ============================================================

    @Test
    void tamper_headerByte_rejected() throws Exception {
        Path plain = writeRandomFile("plain.bin", 300_000);
        Path enc = tempDir.resolve("plain.bin.enc");
        Path dec = tempDir.resolve("plain.bin.dec");

        HMAC.processFile(HMAC.ENCRYPT_MODE, plain.toFile(), enc.toFile(), KEY1);

        // Flip a byte in the first few bytes (header zone)
        flipOneByte(enc, 0);

        assertThrows(Exception.class, () -> HMAC.processFile(HMAC.DECRYPT_MODE, enc.toFile(), dec.toFile(), KEY1));
    }

    // ============================================================
    // 5) Tamper: flip a byte in tag (should fail)
    // ============================================================

    @Test
    void tamper_tagByte_rejected() throws Exception {
        Path plain = writeRandomFile("plain.bin", 300_000);
        Path enc = tempDir.resolve("plain.bin.enc");
        Path dec = tempDir.resolve("plain.bin.dec");

        HMAC.processFile(HMAC.ENCRYPT_MODE, plain.toFile(), enc.toFile(), KEY1);

        // If your format is [FIELDS][TAG][CIPHERTEXT], TAG starts at fixed offset.
        // Update these offsets to match YOUR HMAC class constants.
        int fieldsLen = HMAC.FIELDS_LEN; // make it public or duplicate here
        flipOneByte(enc, fieldsLen); // flip first byte of tag

        assertThrows(Exception.class, () -> HMAC.processFile(HMAC.DECRYPT_MODE, enc.toFile(), dec.toFile(), KEY1));
    }

    // ============================================================
    // 6) Truncated file: should fail ("too small" / "bad format")
    // ============================================================

    @Test
    void truncatedFile_rejected() throws Exception {
        Path plain = writeRandomFile("plain.bin", 200_000);
        Path enc = tempDir.resolve("plain.bin.enc");
        Path dec = tempDir.resolve("plain.bin.dec");

        HMAC.processFile(HMAC.ENCRYPT_MODE, plain.toFile(), enc.toFile(), KEY1);

        byte[] all = Files.readAllBytes(enc);
        byte[] truncated = new byte[Math.max(0, all.length / 2)];
        System.arraycopy(all, 0, truncated, 0, truncated.length);
        Files.write(enc, truncated);

        assertThrows(Exception.class, () -> HMAC.processFile(HMAC.DECRYPT_MODE, enc.toFile(), dec.toFile(), KEY1));
    }

    // ============================================================
    // 7) Empty input: encrypt then decrypt should succeed (PKCS7 handles it)
    // ============================================================

    @Test
    void emptyFile_roundTrip_ok() throws Exception {
        Path plain = tempDir.resolve("empty.bin");
        Files.write(plain, new byte[0]);

        Path enc = tempDir.resolve("empty.bin.enc");
        Path dec = tempDir.resolve("empty.bin.dec");

        HMAC.processFile(HMAC.ENCRYPT_MODE, plain.toFile(), enc.toFile(), KEY1);
        HMAC.processFile(HMAC.DECRYPT_MODE, enc.toFile(), dec.toFile(), KEY1);

        assertArrayEquals(new byte[0], Files.readAllBytes(dec));
    }
}
