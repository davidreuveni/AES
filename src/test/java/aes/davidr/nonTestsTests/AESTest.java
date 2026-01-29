package aes.davidr.nonTestsTests;

import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import aes.davidr.engine.AES;
import aes.davidr.engine.KeySchedule;

public class AESTest {

    private static final int SIZE_MB = 128; 

    public static void main(String[] args) throws Exception {
        testRandomRounds(200); // random round-trip tests
        benchmarkAES(SIZE_MB);
        benchmarkJavaAES(SIZE_MB);
        System.out.println("✅ All AES tests passed.");

    }

    // ---- Test: random round-trip tests ----
    private static void testRandomRounds(int count) {
        SecureRandom rnd = new SecureRandom();
        for (int i = 0; i < count; i++) {
            byte[] key = new byte[16];
            rnd.nextBytes(key);

            KeySchedule ke = new KeySchedule(key);

            byte[] pt = randomState(rnd);
            byte[] st = pt.clone();

            AES.blockRun(AES.ENCRYPT_MODE, st, ke);
            AES.blockRun(AES.DECRYPT_MODE, st, ke);

            if (!Arrays.equals(st, pt)) {
                System.out.println("❌ Random round-trip failed at i=" + i);
                System.out.println("Key:   " + key);
                System.out.println("Plain:");
                printMatrix(pt);
                System.out.println("Back:");
                printMatrix(st);
                throw new AssertionError("Random round-trip failed");
            }
        }
        System.out.println("✅ " + count + " random round-trips passed.\n");
    }

    // ---------- BENCHMARK ----------
    // Measures encrypt/decrypt speed over approx `megabytes` of data.
    // Prints MB/s and ETA for 5 GB.
    private static void benchmarkAES(int megabytes) {
        final int BLOCK = 16; // AES block size
        final long totalBytes = (long) megabytes * 1024 * 1024;
        final long blocks = totalBytes / BLOCK;

        SecureRandom rnd = new SecureRandom();
        byte[] key = new byte[16];
        rnd.nextBytes(key);

        // Single state we mutate each iteration (keeps allocations low)
        byte[] state = randomState(rnd);

        KeySchedule ke = new KeySchedule(key);

        // Reset state after warmup
        state = randomState(rnd);

        // --- Measure ENCRYPT ---
        long t0 = System.nanoTime();
        for (long i = 0; i < blocks; i++) {
            AES.blockRun(AES.ENCRYPT_MODE, state, ke);
        }
        long t1 = System.nanoTime();

        // --- Measure DECRYPT ---
        for (int i = 0; i < 4; i++) { // re-randomize state a bit
            state = randomState(rnd);
        }
        long t2 = System.nanoTime();
        for (long i = 0; i < blocks; i++) {
            AES.blockRun(AES.DECRYPT_MODE, state, ke);
        }
        long t3 = System.nanoTime();

        double encSec = (t1 - t0) / 1e9;
        double decSec = (t3 - t2) / 1e9;

        double encMBps = (totalBytes / (1024.0 * 1024.0)) / encSec;
        double decMBps = (totalBytes / (1024.0 * 1024.0)) / decSec;

        double fiveGB = 5.0 * 1024.0; // MB in 5 GB
        double encETAsec = fiveGB / encMBps;
        double decETAsec = fiveGB / decMBps;

        System.out.printf("\n--- AES Benchmark (~%d MB) ---\n", megabytes);
        System.out.printf("Encrypt: %.2f MB/s (%.3f s)\n", encMBps, encSec);
        System.out.printf("Decrypt: %.2f MB/s (%.3f s)\n", decMBps, decSec);
        System.out.printf("Estimated time for 5 GB:\n");
        System.out.printf("  Encrypt: %.2f s (%.2f min)\n", encETAsec, encETAsec / 60.0);
        System.out.printf("  Decrypt: %.2f s (%.2f min)\n\n", decETAsec, decETAsec / 60.0);
    }

    private static void benchmarkJavaAES(int megabytes) throws Exception {
        final int BLOCK = 16; // AES block size
        final long totalBytes = (long) megabytes * 1024 * 1024;
        final long blocks = totalBytes / BLOCK;

        SecureRandom rnd = new SecureRandom();
        byte[] key = new byte[16];
        rnd.nextBytes(key);

        // Single state we mutate each iteration (keeps allocations low)
        byte[] state = randomState(rnd);

        SecretKeySpec ks = new SecretKeySpec(key, "AES");

        // Use AES/ECB/NoPadding so it's block-for-block comparable to your AES.blockRun
        // (single block).
        Cipher enc = Cipher.getInstance("AES/ECB/NoPadding");
        Cipher dec = Cipher.getInstance("AES/ECB/NoPadding");
        enc.init(Cipher.ENCRYPT_MODE, ks);
        dec.init(Cipher.DECRYPT_MODE, ks);

        // output buffer to avoid allocations inside the loop
        byte[] out = new byte[BLOCK];

        // Reset state after warmup
        state = randomState(rnd);

        // --- Measure ENCRYPT ---
        long t0 = System.nanoTime();
        for (long i = 0; i < blocks; i++) {
            enc.doFinal(state, 0, BLOCK, out, 0);
            System.arraycopy(out, 0, state, 0, BLOCK);
        }
        long t1 = System.nanoTime();

        // --- Measure DECRYPT ---
        for (int i = 0; i < 4; i++) { // re-randomize state a bit
            state = randomState(rnd);
        }
        long t2 = System.nanoTime();
        for (long i = 0; i < blocks; i++) {
            dec.doFinal(state, 0, BLOCK, out, 0);
            System.arraycopy(out, 0, state, 0, BLOCK);
        }
        long t3 = System.nanoTime();

        double encSec = (t1 - t0) / 1e9;
        double decSec = (t3 - t2) / 1e9;

        double encMBps = (totalBytes / (1024.0 * 1024.0)) / encSec;
        double decMBps = (totalBytes / (1024.0 * 1024.0)) / decSec;

        double fiveGB = 5.0 * 1024.0; // MB in 5 GB
        double encETAsec = fiveGB / encMBps;
        double decETAsec = fiveGB / decMBps;

        System.out.printf("\n--- Java AES (JCE) Benchmark (~%d MB) ---\n", megabytes);
        System.out.printf("Encrypt: %.2f MB/s (%.3f s)\n", encMBps, encSec);
        System.out.printf("Decrypt: %.2f MB/s (%.3f s)\n", decMBps, decSec);
        System.out.printf("Estimated time for 5 GB:\n");
        System.out.printf("  Encrypt: %.2f s (%.2f min)\n", encETAsec, encETAsec / 60.0);
        System.out.printf("  Decrypt: %.2f s (%.2f min)\n\n", decETAsec, decETAsec / 60.0);
    }

    // ---- Helpers ----
    private static byte[] randomState(SecureRandom rnd) {
        byte[] block = new byte[16];
        rnd.nextBytes(block);
        return block;
    }

    public static void printMatrix(byte[] m) {
        for (int i = 0; i < 16; i++) {

            System.out.printf("%02X ", m[i]);

            System.out.println();
        }
        System.out.println();
    }

    public static byte[] hex(String s) {
        s = s.replaceAll("[^0-9A-Fa-f]", ""); // keep only hex chars
        if ((s.length() & 1) != 0)
            throw new IllegalArgumentException("Odd hex length: " + s.length());

        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(s.charAt(i * 2), 16);
            int lo = Character.digit(s.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0)
                throw new IllegalArgumentException("Bad hex at byte " + i);
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

}
