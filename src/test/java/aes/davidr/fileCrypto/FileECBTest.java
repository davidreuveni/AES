package aes.davidr.fileCrypto;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.ResourceLock;

import aes.davidr.engine.KeySchedule;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Comparator;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FileECBTest {

    @TempDir
    Path tempDir;

    @SuppressWarnings("unused")
    @Test
    @ResourceLock("ECB_FILE_IO")
    void testProcessFile() throws URISyntaxException, IOException {

        byte[] key = {
                0x00, 0x01, 0x02, 0x03,
                0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B,
                0x0C, 0x0D, 0x0E, 0x0F
        };
        KeySchedule ks = new KeySchedule(key);

        // 1) Preferred file path (your original)
        Path preferred = Paths.get("src/test/java/aes/davidr/test.d");

        // 2) Fallback seed path (CHANGE THIS to wherever you keep a test copy)
        Path fallbackSeed = Paths.get("src\\test\\java\\aes\\davidr\\test.d");

        // Decide which source to use
        Path source = Files.exists(preferred) ? preferred : fallbackSeed;

        assertTrue(Files.exists(source),
                "Test file not found. Missing both:\n  preferred=" + preferred + "\n  fallback=" + fallbackSeed);

        // Work only in temp dir so we don't delete/overwrite real files
        Path plain = tempDir.resolve("test.d");
        Path enc   = tempDir.resolve("test.d.enc");
        Path dec   = tempDir.resolve("test.d.dec");

        // Copy the source file into temp location
        Files.copy(source, plain, StandardCopyOption.REPLACE_EXISTING);

        long totalBytes = Files.size(plain);
        double megabytes = totalBytes / (1024.0 * 1024.0);

        // --- Measure ENCRYPT ---
        long t0 = System.nanoTime();
        FileECB.processFile(FileECB.ENCRYPT_MODE, plain.toFile(), enc.toFile(), ks);
        long t1 = System.nanoTime();

        // --- Measure DECRYPT ---
        long t2 = System.nanoTime();
        FileECB.processFile(FileECB.DECRYPT_MODE, enc.toFile(), dec.toFile(), ks);
        long t3 = System.nanoTime();

        double encSec = (t1 - t0) / 1e9;
        double decSec = (t3 - t2) / 1e9;

        double encMBps = megabytes / encSec;
        double decMBps = megabytes / decSec;

        double fiveGB_MB = 5.0 * 1024.0; // MB in 5 GB
        double encETAsec = fiveGB_MB / encMBps;
        double decETAsec = fiveGB_MB / decMBps;

        // System.out.printf("\n--- AES Benchmark (~%.2f MB) ---\n", megabytes);
        // System.out.printf("Encrypt: %.2f MB/s (%.3f s)\n", encMBps, encSec);
        // System.out.printf("Decrypt: %.2f MB/s (%.3f s)\n", decMBps, decSec);
        // System.out.printf("Estimated time for 5 GB:\n");
        // System.out.printf("  Encrypt: %.2f s (%.2f min)\n", encETAsec, encETAsec / 60.0);
        // System.out.printf("  Decrypt: %.2f s (%.2f min)\n\n", decETAsec, decETAsec / 60.0);

        // Validate correctness: decrypted file must match original plain file
        byte[] originalBytes = Files.readAllBytes(plain);
        byte[] decryptedBytes = Files.readAllBytes(dec);
        assertArrayEquals(originalBytes, decryptedBytes, "Decrypted file differs from original!");
    
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
