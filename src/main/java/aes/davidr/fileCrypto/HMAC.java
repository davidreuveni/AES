package aes.davidr.fileCrypto;

import aes.davidr.engine.KeySchedule;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.security.MessageDigest;

public class HMAC {
    public static final boolean ENCRYPT_MODE = true;
    public static final boolean DECRYPT_MODE = false;

    private static final byte[] MAGIC   = new byte[]{'D','R','E','C','B','M','A','C'}; // 8 bytes
    private static final byte   VERSION = 1;
    private static final byte   MODE_ECB = 0;
    private static final int TAG_LEN = 32; // HMAC-SHA256 output length
    static final int FIELDS_LEN = 8 + 1 + 1 + 8;
    static final int HEADER_LEN = FIELDS_LEN + TAG_LEN;
    private static final int TAG_OFFSET = FIELDS_LEN;

    public static void processFile(boolean mode, File in, File out, byte[] mainKey) throws Exception {
        if (mode) {
            encrypt(in, out, mainKey);
        } else {
            decrypt(in, out, mainKey);
        }
    }

    private static void encrypt(File plainIn, File outEnc, byte[] mainKey) throws Exception {
        if (plainIn == null || outEnc == null || mainKey == null) throw new IllegalArgumentException("null");
        DerivedKeys dk = deriveKeys(mainKey);

        long plainLen = plainIn.length();
        byte[] fields = buildFields(plainLen);

        try (OutputStream os = new BufferedOutputStream(new FileOutputStream(outEnc), 64 * 1024)) {
            os.write(fields);
            os.write(new byte[TAG_LEN]); // placeholder
        }

        Mac mac = initHmac(dk.macKey);
        mac.update(fields);

        try (InputStream is = new BufferedInputStream(new FileInputStream(plainIn), 64 * 1024);
             OutputStream fosAppend = new FileOutputStream(outEnc, true);
             OutputStream osCipher = new BufferedOutputStream(new MacOutputStream(fosAppend, mac), 64 * 1024)) {

            // uses your existing stream encryption logic
            FileECB.encryptIStoOS(is, osCipher, dk.ks);
            osCipher.flush();
        }

        // 4) Finalize HMAC and write tag into the header (seek)
        byte[] tag = mac.doFinal();
        writeTagIntoHeader(outEnc, tag);
    }

    private static void decrypt(File encIn, File plainOut, byte[] mainKey) throws Exception {
        if (encIn == null || plainOut == null || mainKey == null) throw new IllegalArgumentException("null");
        DerivedKeys dk = deriveKeys(mainKey);

        Header h = readAndValidateHeader(encIn);
        verifyHmacOrThrow(encIn, h, dk.macKey);

        try (InputStream is = new BufferedInputStream(new FileInputStream(encIn), 64 * 1024);
             OutputStream os = new BufferedOutputStream(new FileOutputStream(plainOut), 64 * 1024)) {

            skipFully(is, HEADER_LEN);
            FileECB.decryptIStoOS(is, os, dk.ks);
        }

        if (plainOut.length() != h.plaintextLen) {
            throw new IOException("Plaintext length mismatch (wrong key or internal error).");
        }
    }

    private static byte[] buildFields(long plaintextLen) {
        ByteBuffer bb = ByteBuffer.allocate(FIELDS_LEN);
        bb.put(MAGIC);
        bb.put(VERSION);
        bb.put(MODE_ECB);
        bb.putLong(plaintextLen);
        return bb.array();
    }

    private static Header readAndValidateHeader(File encIn) throws IOException {
        long fileLen = encIn.length();
        if (fileLen < HEADER_LEN) throw new IOException("Invalid file: too small");

        byte[] fields = new byte[FIELDS_LEN];
        byte[] tag = new byte[TAG_LEN];

        try (InputStream is = new BufferedInputStream(new FileInputStream(encIn), 64 * 1024)) {
            readFully(is, fields, 0, fields.length);
            readFully(is, tag, 0, tag.length);
        }

        // validate magic
        for (int i = 0; i < MAGIC.length; i++) {
            if (fields[i] != MAGIC[i]) throw new IOException("Invalid file: bad MAGIC");
        }

        // validate version
        byte ver = fields[8];
        if (ver != VERSION) throw new IOException("Unsupported VERSION: " + ver);

        // validate mode
        byte mode = fields[9];
        if (mode != MODE_ECB) throw new IOException("Unsupported MODE: " + mode);

        // parse plaintext length
        long plainLen = ByteBuffer.wrap(fields, 10, 8).getLong();
        if (plainLen < 0) throw new IOException("Invalid plaintext length in header");

        return new Header(fields, tag, plainLen);
    }

    /** Overwrite the placeholder tag at TAG_OFFSET. */
    private static void writeTagIntoHeader(File outEnc, byte[] tag) throws IOException {
        if (tag.length != TAG_LEN) throw new IllegalArgumentException("bad tag len");
        try (RandomAccessFile raf = new RandomAccessFile(outEnc, "rw")) {
            raf.seek(TAG_OFFSET);
            raf.write(tag);
        }
    }

    private static void verifyHmacOrThrow(File encIn, Header h, byte[] macKey) throws Exception {
        Mac mac = initHmac(macKey);

        // HMAC input: fields || ciphertext
        mac.update(h.fields);

        // stream ciphertext bytes (from HEADER_LEN to EOF) into mac
        try (InputStream is = new BufferedInputStream(new FileInputStream(encIn), 64 * 1024)) {
            skipFully(is, HEADER_LEN);

            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = is.read(buf)) != -1) {
                mac.update(buf, 0, n);
            }
        }

        byte[] computed = mac.doFinal();

        // constant-time compare
        if (!MessageDigest.isEqual(computed, h.tag)) {
            throw new SecurityException("HMAC verification failed (file modified or wrong key).");
        }
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

    private static void skipFully(InputStream is, long bytes) throws IOException {
        long left = bytes;
        while (left > 0) {
            long s = is.skip(left);
            if (s <= 0) { // skip() is allowed to return 0, so fallback to read
                if (is.read() == -1) throw new EOFException("Unexpected EOF while skipping");
                left--;
            } else {
                left -= s;
            }
        }
    }

    private static void readFully(InputStream is, byte[] b, int off, int len) throws IOException {
        int got = 0;
        while (got < len) {
            int n = is.read(b, off + got, len - got);
            if (n == -1) throw new EOFException("Unexpected EOF");
            got += n;
        }
    }

    /** OutputStream wrapper: every write also updates the Mac with the same ciphertext bytes. */
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

    private static final class DerivedKeys {
        final KeySchedule ks;
        final byte[] macKey;
        DerivedKeys(KeySchedule ks, byte[] macKey) { this.ks = ks; this.macKey = macKey; }
    }

    private static final class Header {
        final byte[] fields;    // authenticated fields bytes
        final byte[] tag;       // stored tag from header
        final long plaintextLen;
        Header(byte[] fields, byte[] tag, long plaintextLen) {
            this.fields = fields;
            this.tag = tag;
            this.plaintextLen = plaintextLen;
        }
    }
}
