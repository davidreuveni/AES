package aes.davidr.modes;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import aes.davidr.engine.AES;
import aes.davidr.engine.KeySchedule;

import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.*;

public class AESCompareAll {

    // Tune: target 256KB–4MB per task (must be multiple of 16)
    static final int TASK_BYTES = 1 * 1024 * 1024; // 1MB per task

    public static void main(String[] args) throws Exception {
        final int sizeMB = 32; // must be multiple of 16 bytes
        final byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);

        final byte[] plaintext = new byte[sizeMB * 1024 * 1024];
        new SecureRandom().nextBytes(plaintext);
        if ((plaintext.length % 16) != 0) {
            throw new IllegalStateException("plaintext length must be multiple of 16");
        }

        // warmup (JIT)
        warmup(key, Arrays.copyOf(plaintext, 4 * 1024 * 1024)); // 4MB sample

        KeySchedule ks = new KeySchedule(key);

        // --- Custom AES: Serial ---
        Timed<byte[]> tCustomEnc = time(() -> customEcbSerialEncrypt(plaintext, ks));
        Timed<byte[]> tCustomDec = time(() -> customEcbSerialDecrypt(tCustomEnc.value, ks));
        checkEqual("Custom serial round-trip", plaintext, tCustomDec.value);
        report("Custom AES (Serial, ECB)", plaintext.length, tCustomEnc.seconds, tCustomDec.seconds);

        // --- Custom AES: Parallel ---
        Timed<byte[]> tParEnc = time(() -> customEcbParallelEncrypt(plaintext, ks));
        Timed<byte[]> tParDec = time(() -> customEcbParallelDecrypt(tParEnc.value, ks));
        checkEqual("Custom parallel round-trip", plaintext, tParDec.value);
        report("Custom AES (Parallel, ECB)", plaintext.length, tParEnc.seconds, tParDec.seconds);

        // --- Java Cipher (AES/ECB/NoPadding) ---
        Timed<byte[]> tJceEnc = time(() -> jceEncryptECB(plaintext, key));
        Timed<byte[]> tJceDec = time(() -> jceDecryptECB(tJceEnc.value, key));
        checkEqual("JCE AES round-trip", plaintext, tJceDec.value);
        report("Java Cipher AES (ECB/NoPadding)", plaintext.length, tJceEnc.seconds, tJceDec.seconds);

        // Optional: cross-check your cipher output vs JCE (should match for ECB/NoPadding)
        byte[] customCt = customEcbSerialEncrypt(plaintext, ks);
        byte[] jceCt = jceEncryptECB(plaintext, key);
        checkEqual("Custom == JCE ciphertext (ECB)", customCt, jceCt);

        System.out.println("\n✅ All comparisons passed.");
    }

    // ===== Correct Custom ECB using blockRun on 16-byte blocks =====

    private static byte[] customEcbSerialEncrypt(byte[] pt, KeySchedule ks) {
        return customEcbSerial(pt, ks, true);
    }

    private static byte[] customEcbSerialDecrypt(byte[] ct, KeySchedule ks) {
        return customEcbSerial(ct, ks, false);
    }

    private static byte[] customEcbSerial(byte[] in, KeySchedule ks, boolean encrypt) {
        if (in.length % 16 != 0) throw new IllegalArgumentException("len % 16 != 0");

        byte[] out = Arrays.copyOf(in, in.length);
        // byte[] block = new byte[16];

        for (int off = 0; off < out.length; off += 16) {
            // System.arraycopy(out, off, block, 0, 16);
            AES.blockRun(encrypt, out, ks, off);  // <-- unchanged blockRun
            // System.arraycopy(block, 0, out, off, 16);
        }
        return out;
    }

    private static byte[] customEcbParallelEncrypt(byte[] pt, KeySchedule ks) throws Exception {
        return customEcbParallel(pt, ks, true);
    }

    private static byte[] customEcbParallelDecrypt(byte[] ct, KeySchedule ks) throws Exception {
        return customEcbParallel(ct, ks, false);
    }

    private static byte[] customEcbParallel(byte[] in, KeySchedule ks, boolean encrypt) throws Exception {
        if (in.length % 16 != 0) throw new IllegalArgumentException("len % 16 != 0");

        byte[] out = Arrays.copyOf(in, in.length);

        int threads = Math.min(Runtime.getRuntime().availableProcessors(), Math.max(1, out.length / TASK_BYTES));
        ExecutorService pool = Executors.newFixedThreadPool(threads);

        final int taskBytes = (TASK_BYTES / 16) * 16; // force multiple of 16
        List<Future<?>> futures = new ArrayList<>();

        for (int start = 0; start < out.length; start += taskBytes) {
            final int s = start;
            final int e = Math.min(out.length, s + taskBytes);
            futures.add(pool.submit(() -> {
                // byte[] block = new byte[16];
                for (int off = s; off < e; off += 16) {
                    // System.arraycopy(out, off, block, 0, 16);
                    AES.blockRun(encrypt, out, ks, off); // <-- unchanged blockRun
                    // System.arraycopy(block, 0, out, off, 16);
                }
            }));
        }

        for (Future<?> f : futures) f.get();
        pool.shutdown();
        return out;
    }

    // ===== JCE AES/ECB/NoPadding =====
    private static byte[] jceEncryptECB(byte[] pt, byte[] key) throws Exception {
        SecretKeySpec k = new SecretKeySpec(key, "AES");
        Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, k);
        return processWithCipher(c, pt);
    }

    private static byte[] jceDecryptECB(byte[] ct, byte[] key) throws Exception {
        SecretKeySpec k = new SecretKeySpec(key, "AES");
        Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
        c.init(Cipher.DECRYPT_MODE, k);
        return processWithCipher(c, ct);
    }

    private static byte[] processWithCipher(Cipher cipher, byte[] in) throws Exception {
        byte[] out = new byte[in.length];
        final int CHUNK = 16 * 1024;
        int off = 0;
        while (off < in.length) {
            int len = Math.min(CHUNK, in.length - off);
            int wrote = cipher.update(in, off, len, out, off);
            if (wrote != len) throw new IllegalStateException("Cipher.update wrote unexpected size");
            off += len;
        }
        byte[] tail = cipher.doFinal();
        if (tail.length != 0) throw new IllegalStateException("Unexpected tail bytes from doFinal");
        return out;
    }

    // ===== Timing / reporting =====
    private static class Timed<T> {
        final T value;
        final double seconds;
        Timed(T v, double s) { value = v; seconds = s; }
    }

    private static <T> Timed<T> time(Callable<T> job) throws Exception {
        long t0 = System.nanoTime();
        T v = job.call();
        long t1 = System.nanoTime();
        return new Timed<>(v, (t1 - t0) / 1e9);
    }

    private static void report(String label, int totalBytes, double encSec, double decSec) {
        double mb = totalBytes / (1024.0 * 1024.0);
        double encMBps = mb / encSec;
        double decMBps = mb / decSec;
        double fiveGB = 5.0 * 1024.0; // MB
        System.out.printf("\n--- %s Benchmark (~%.0f MB) ---\n", label, mb);
        System.out.printf("Encrypt: %.2f MB/s (%.3f s)\n", encMBps, encSec);
        System.out.printf("Decrypt: %.2f MB/s (%.3f s)\n", decMBps, decSec);
        System.out.printf("Estimated time for 5 GB:\n");
        System.out.printf("  Encrypt: %.2f s (%.2f min)\n", fiveGB / encMBps, (fiveGB / encMBps) / 60.0);
        System.out.printf("  Decrypt: %.2f s (%.2f min)\n", fiveGB / decMBps, (fiveGB / decMBps) / 60.0);
    }

    private static void checkEqual(String label, byte[] a, byte[] b) {
        if (!Arrays.equals(a, b)) throw new AssertionError("Mismatch: " + label);
    }

    private static void warmup(byte[] key, byte[] sample) throws Exception {
        KeySchedule ks = new KeySchedule(key);
        customEcbSerialEncrypt(sample, ks);
        customEcbSerialDecrypt(customEcbSerialEncrypt(sample, ks), ks);
        jceDecryptECB(jceEncryptECB(sample, key), key);
        customEcbParallelEncrypt(sample, ks);
        customEcbParallelDecrypt(customEcbParallelEncrypt(sample, ks), ks);
    }
}
