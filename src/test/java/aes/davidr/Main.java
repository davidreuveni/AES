package aes.davidr;

import aes.davidr.engine.KeySchedule;
import aes.davidr.fileCrypto.FileECB;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Comparator;

public class Main {

    //changes made by me
    public static void main(String[] args) throws IOException{
    
        KeySchedule ks = new KeySchedule("");

        // 1) Preferred file path (your original)
        Path preferred = Paths.get("src\\test\\java\\aes\\davidr\\test.d");

        // 2) Fallback seed path (CHANGE THIS to wherever you keep a test copy)
        Path fallbackSeed = Paths.get("src\\test\\java\\aes\\davidr\\test.d");

        // Work only in temp dir so we don't delete/overwrite real files
        Path tempDir = Files.createTempDirectory("aes-benchmark");
        Path plain = tempDir.resolve("test.d");
        Path enc   = tempDir.resolve("test.d.enc");
        Path dec   = tempDir.resolve("test.d.dec");

        // Copy the source file into temp location
        Path source = Files.exists(preferred) ? preferred : fallbackSeed;
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

        System.out.printf("\n--- AES Benchmark (~%.2f MB) ---\n", megabytes);
        System.out.printf("Encrypt: %.2f MB/s (%.3f s)\n", encMBps, encSec);
        System.out.printf("Decrypt: %.2f MB/s (%.3f s)\n", decMBps, decSec);
        System.out.printf("Estimated time for 5 GB:\n");
        System.out.printf("  Encrypt: %.2f s (%.2f min)\n", encETAsec, encETAsec / 60.0);
        System.out.printf("  Decrypt: %.2f s (%.2f min)\n\n", decETAsec, decETAsec / 60.0);

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
