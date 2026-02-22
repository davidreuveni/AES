package aes.davidr.fileCrypto;

import aes.davidr.engine.KeySchedule;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.security.MessageDigest;

/**
 * Streaming format (tag at end):
 *   [fields (MAGIC+VERSION+MODE)] [ciphertext ...] [tag (32)]
 *
 * HMAC input:
 *   fields || ciphertext
 *
 * Notes:
 * - No plaintext length in header (stream-friendly).
 * - Decrypt spools ciphertext to a temp file to verify MAC before emitting plaintext.
 */
public final class HMAC {

    public static final boolean ENCRYPT_MODE = true;
    public static final boolean DECRYPT_MODE = false;

    private static final byte[] MAGIC   = new byte[]{'D','R','E','C','B','M','A','C'}; // 8 bytes
    private static final byte   VERSION = 1;
    private static final byte   MODE_ECB = 0;

    private static final int TAG_LEN    = 32;        // HMAC-SHA256
    private static final int BUF        = 64 * 1024; // IO buffer

    // fields = MAGIC(8) + VERSION(1) + MODE(1)
    static final int FIELDS_LEN = 8 + 1 + 1;

    public static void processFile(boolean mode, File in, File out, byte[] mainKey) throws Exception {
        if (mode) {
            try (InputStream is = new BufferedInputStream(new FileInputStream(in), BUF);
                 OutputStream os = new BufferedOutputStream(new FileOutputStream(out), BUF)) {
                encryptIStoOS(is, os, mainKey);
            }
        } else {
            try (InputStream is = new BufferedInputStream(new FileInputStream(in), BUF);
                 OutputStream os = new BufferedOutputStream(new FileOutputStream(out), BUF)) {
                decryptIStoOS(is, os, mainKey);
            }
        }
    }

    public static void cipherStream(boolean mode, InputStream in, OutputStream out, byte[] mainKey) throws Exception {
        if (mode) encryptIStoOS(in, out, mainKey);
        else decryptIStoOS(in, out, mainKey);
    }

    /**
     * Encrypt plaintext stream -> writes fields + ciphertext + tag to outEnc.
     * Does NOT close the provided streams.
     */
    public static void encryptIStoOS(InputStream plainIn, OutputStream outEnc, byte[] mainKey) throws Exception {
        if (plainIn == null || outEnc == null || mainKey == null) throw new IllegalArgumentException("null");

        DerivedKeys dk = deriveKeys(mainKey);
        byte[] fields = buildFields();

        Mac mac = initHmac(dk.macKey);
        mac.update(fields);

        // Avoid closing caller's OutputStream
        OutputStream encOut = new BufferedOutputStream(new NonClosingOutputStream(outEnc), BUF);

        // 1) write fields
        encOut.write(fields);

        // 2) stream ciphertext while updating MAC
        try (OutputStream macOut = new BufferedOutputStream(new MacOutputStream(encOut, mac), BUF)) {
            FileECB.encryptIStoOS(plainIn, macOut, dk.ks);
            macOut.flush();
        }

        // 3) finalize + write tag at end
        byte[] tag = mac.doFinal();
        encOut.write(tag);
        encOut.flush();
    }

    /**
     * Decrypt encrypted stream (fields + ciphertext + tag) -> writes plaintext to plainOut.
     * Verifies HMAC BEFORE decrypting (spools ciphertext to temp file).
     * Does NOT close the provided streams.
     */
    public static void decryptIStoOS(InputStream encIn, OutputStream plainOut, byte[] mainKey) throws Exception {
        if (encIn == null || plainOut == null || mainKey == null) throw new IllegalArgumentException("null");

        DerivedKeys dk = deriveKeys(mainKey);

        InputStream in = new BufferedInputStream(encIn, BUF);

        // 1) read/validate fields
        byte[] fields = new byte[FIELDS_LEN];
        readFully(in, fields, 0, fields.length);
        validateFields(fields);

        // 2) MAC over fields || ciphertext
        Mac mac = initHmac(dk.macKey);
        mac.update(fields);

        // 3) Spool ciphertext to temp while keeping last TAG_LEN bytes as tag (ring buffer)
        File tmp = File.createTempFile("hmac_ecb_cipher_", ".bin");
        // Optional: best-effort cleanup if JVM exits unexpectedly
        tmp.deleteOnExit();

        byte[] ring = new byte[TAG_LEN];
        int filled = 0;
        int pos = 0; // next index to evict/overwrite when ring full

        long bytesAfterFields = 0;

        try (OutputStream tmpOut = new BufferedOutputStream(new FileOutputStream(tmp), BUF)) {
            byte[] buf = new byte[BUF];
            int n;
            while ((n = in.read(buf)) != -1) {
                bytesAfterFields += n;
                for (int i = 0; i < n; i++) {
                    byte b = buf[i];
                    if (filled < TAG_LEN) {
                        ring[filled++] = b;
                        if (filled == TAG_LEN) pos = 0;
                    } else {
                        // evict oldest -> ciphertext
                        byte c = ring[pos];
                        tmpOut.write(c);
                        mac.update(c);

                        // store new byte
                        ring[pos] = b;
                        pos++;
                        if (pos == TAG_LEN) pos = 0;
                    }
                }
            }
            tmpOut.flush();
        }

        if (bytesAfterFields < TAG_LEN) {
            safeDelete(tmp);
            throw new IOException("Invalid file: missing tag (too short)");
        }

        // reconstruct stored tag in correct order from ring buffer
        byte[] storedTag = new byte[TAG_LEN];
        for (int i = 0; i < TAG_LEN; i++) {
            storedTag[i] = ring[(pos + i) % TAG_LEN];
        }

        byte[] computed = mac.doFinal();

        if (!MessageDigest.isEqual(computed, storedTag)) {
            safeDelete(tmp);
            throw new SecurityException("HMAC verification failed (modified file or wrong key).");
        }

        // 4) decrypt ciphertext from temp -> plaintext output
        OutputStream out = new BufferedOutputStream(new NonClosingOutputStream(plainOut), BUF);
        try (InputStream cipherIn = new BufferedInputStream(new FileInputStream(tmp), BUF)) {
            FileECB.decryptIStoOS(cipherIn, out, dk.ks);
            out.flush();
        } finally {
            safeDelete(tmp);
        }
    }


    private static byte[] buildFields() {
        ByteBuffer bb = ByteBuffer.allocate(FIELDS_LEN);
        bb.put(MAGIC);
        bb.put(VERSION);
        bb.put(MODE_ECB);
        return bb.array();
    }

    private static void validateFields(byte[] fields) throws IOException {
        // magic
        for (int i = 0; i < MAGIC.length; i++) {
            if (fields[i] != MAGIC[i]) throw new IOException("Invalid file: bad MAGIC");
        }
        // version
        byte ver = fields[8];
        if (ver != VERSION) throw new IOException("Unsupported VERSION: " + ver);
        // mode
        byte mode = fields[9];
        if (mode != MODE_ECB) throw new IOException("Unsupported MODE: " + mode);
    }

    private static Mac initHmac(byte[] macKey) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(macKey, "HmacSHA256"));
        return mac;
    }

    private static DerivedKeys deriveKeys(byte[] mainKey) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        sha.update(mainKey);
        sha.update((byte) 0x02);
        byte[] macKey32 = sha.digest();

        return new DerivedKeys(new KeySchedule(mainKey), macKey32);
    }

    private static void readFully(InputStream is, byte[] b, int off, int len) throws IOException {
        int got = 0;
        while (got < len) {
            int n = is.read(b, off + got, len - got);
            if (n == -1) throw new EOFException("Unexpected EOF");
            got += n;
        }
    }

    private static void safeDelete(File f) {
        try { if (f != null) f.delete(); } catch (Exception ignored) {}
    }

    private static final class MacOutputStream extends FilterOutputStream {
        private final Mac mac;

        MacOutputStream(OutputStream out, Mac mac) {
            super(out);
            this.mac = mac;
        }

        @Override public void write(int b) throws IOException {
            out.write(b);
            mac.update((byte) b);
        }

        @Override public void write(byte[] b, int off, int len) throws IOException {
            out.write(b, off, len);
            mac.update(b, off, len);
        }
    }

    private static final class NonClosingOutputStream extends FilterOutputStream {
        NonClosingOutputStream(OutputStream out) { super(out); }
        @Override public void close() throws IOException { flush(); } // don't close underlying
    }

    private static final class DerivedKeys {
        final KeySchedule ks;
        final byte[] macKey;
        DerivedKeys(KeySchedule ks, byte[] macKey) { this.ks = ks; this.macKey = macKey; }
    }
}