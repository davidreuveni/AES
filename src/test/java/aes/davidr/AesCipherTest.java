package aes.davidr;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AesCipherTest {

    @TempDir
    Path tempDir;

    @Test
    void cryptBytes_withStringKey_roundTripDefaultMode() {
        byte[] plain = "hello aes".getBytes(StandardCharsets.UTF_8);
        String key = "password123";

        byte[] cipher = AesCipher.cryptBytes(AesCipher.ENCRYPT_MODE, plain, key);
        byte[] restored = AesCipher.cryptBytes(AesCipher.DECRYPT_MODE, cipher, key);

        assertArrayEquals(plain, restored);
    }

    @Test
    void cryptBytes_withByteKey_roundTripAutoMode() {
        byte[] plain = "byte-key round trip".getBytes(StandardCharsets.UTF_8);
        byte[] key = "0123456789abcdef".getBytes(StandardCharsets.UTF_8); // 16 bytes

        byte[] cipher = AesCipher.cryptBytes(AesCipher.ENCRYPT_MODE, plain, key);
        byte[] restored = AesCipher.cryptBytes(AesCipher.DECRYPT_MODE, cipher, key);

        assertArrayEquals(plain, restored);
    }

    @Test
    void cryptBytes_withExplicitMode_roundTripAes256() {
        byte[] plain = "explicit mode test payload".getBytes(StandardCharsets.UTF_8);
        String key = "my-secret-passphrase";

        byte[] cipher = AesCipher.cryptBytes(AesCipher.ENCRYPT_MODE, plain, key, AesCipher.AES_256);
        byte[] restored = AesCipher.cryptBytes(AesCipher.DECRYPT_MODE, cipher, key, AesCipher.AES_256);

        assertArrayEquals(plain, restored);
    }

    @Test
    void cryptBytes_withNullByteKey_throws() {
        byte[] plain = "data".getBytes(StandardCharsets.UTF_8);

        assertThrows(IllegalArgumentException.class,
                () -> AesCipher.cryptBytes(AesCipher.ENCRYPT_MODE, plain, (byte[]) null));
    }

    @Test
    void cryptFile_withStringKey_roundTripDefaultMode() throws Exception {
        byte[] plain = "file test content\nline2".getBytes(StandardCharsets.UTF_8);
        String key = "file-key-123";

        Path in = tempDir.resolve("in.bin");
        Path enc = tempDir.resolve("enc.bin");
        Path out = tempDir.resolve("out.bin");
        Files.write(in, plain);

        AesCipher.cryptFile(AesCipher.ENCRYPT_MODE, in.toFile(), enc.toFile(), key);
        AesCipher.cryptFile(AesCipher.DECRYPT_MODE, enc.toFile(), out.toFile(), key);

        assertArrayEquals(plain, Files.readAllBytes(out));
    }

    @Test
    void cryptFile_withByteKeyAndMode_roundTripAes192() throws Exception {
        byte[] plain = "another file payload".getBytes(StandardCharsets.UTF_8);
        byte[] key = "abcdefghijklmnopqrstuvwx".getBytes(StandardCharsets.UTF_8); // 24 bytes

        File in = tempDir.resolve("in2.bin").toFile();
        File enc = tempDir.resolve("enc2.bin").toFile();
        File out = tempDir.resolve("out2.bin").toFile();
        Files.write(in.toPath(), plain);

        AesCipher.cryptFile(AesCipher.ENCRYPT_MODE, in, enc, key, AesCipher.AES_192);
        AesCipher.cryptFile(AesCipher.DECRYPT_MODE, enc, out, key, AesCipher.AES_192);

        assertArrayEquals(plain, Files.readAllBytes(out.toPath()));
    }

    @Test
    void cipherStream_withByteKey_roundTrip() throws Exception {
        byte[] plain = "stream payload with authentication".getBytes(StandardCharsets.UTF_8);
        byte[] key = "0123456789abcdef".getBytes(StandardCharsets.UTF_8); // 16 bytes

        ByteArrayOutputStream encryptedOut = new ByteArrayOutputStream();
        AesCipher.cipherStream(
                AesCipher.ENCRYPT_MODE,
                new ByteArrayInputStream(plain),
                encryptedOut,
                key);

        byte[] encrypted = encryptedOut.toByteArray();

        ByteArrayOutputStream decryptedOut = new ByteArrayOutputStream();
        AesCipher.cipherStream(
                AesCipher.DECRYPT_MODE,
                new ByteArrayInputStream(encrypted),
                decryptedOut,
                key);

        assertArrayEquals(plain, decryptedOut.toByteArray());
    }

    @Test
    void cipherStream_withWrongKey_throwsSecurityException() throws Exception {
        byte[] plain = "authenticated stream payload".getBytes(StandardCharsets.UTF_8);
        byte[] key = "0123456789abcdef".getBytes(StandardCharsets.UTF_8); // 16 bytes
        byte[] wrongKey = "fedcba9876543210".getBytes(StandardCharsets.UTF_8); // 16 bytes

        ByteArrayOutputStream encryptedOut = new ByteArrayOutputStream();
        AesCipher.cipherStream(
                AesCipher.ENCRYPT_MODE,
                new ByteArrayInputStream(plain),
                encryptedOut,
                key);

        byte[] encrypted = encryptedOut.toByteArray();

        assertThrows(
                SecurityException.class,
                () -> AesCipher.cipherStream(
                        AesCipher.DECRYPT_MODE,
                        new ByteArrayInputStream(encrypted),
                        new ByteArrayOutputStream(),
                        wrongKey));
    }

    @AfterEach
    void cleanup() throws IOException {
        if (Files.exists(tempDir)) {
            Files.walk(tempDir)
                .sorted(Comparator.reverseOrder())
                .forEach(path -> {
                    try {
                        Files.delete(path);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                });
        }
    }
}
