package aes.davidr.fileCrypto;

import aes.davidr.engine.AES;
import aes.davidr.engine.KeySchedule;
import aes.davidr.modes.ECB;
import aes.davidr.modes.Padding;

import java.io.*;

public final class FileECB {
    public static final boolean ENCRYPT_MODE = true;
    public static final boolean DECRYPT_MODE = false;
    private static final int BLOCK = 16;
    private static final int BUF   = 64 * 1024; // will align down to multiple of 16

    private FileECB() {}

    public static void processFile(boolean encrypt, File inFile, File outFile, KeySchedule ks) throws IOException {
        if (inFile == null || outFile == null || ks == null) throw new IllegalArgumentException("null");
        int bufSize = BUF & ~(BLOCK - 1);

        try (InputStream  is = new BufferedInputStream(new FileInputStream(inFile), bufSize);
             OutputStream os = new BufferedOutputStream(new FileOutputStream(outFile), bufSize)) {
            if (encrypt) encryptIStoOS(is, os, ks, bufSize);
            else decryptIStoOS(is, os, ks, bufSize);
        }
    }

    public static void encryptIStoOS(InputStream in, OutputStream out, KeySchedule ks) throws IOException {
        int bufSize = BUF & ~(BLOCK - 1);
        encryptIStoOS(in, out, ks,bufSize);
    }
    private static void encryptIStoOS(InputStream in, OutputStream out, KeySchedule ks, int bufSize) throws IOException {
        byte[] buf   = new byte[bufSize];
        byte[] carry = new byte[BLOCK];
        int carryLen = 0;

        while (true) {
            // preload carry into buf[0..carryLen)
            if (carryLen != 0) System.arraycopy(carry, 0, buf, 0, carryLen);

            int n = in.read(buf, carryLen, buf.length - carryLen);
            if (n == -1) break;

            int total = carryLen + n;
            int full  = total & ~(BLOCK - 1);     // largest multiple of 16
            int rem   = total - full;

            if (full != 0) {
                ECB.ecbProcessBlocks(AES.ENCRYPT_MODE, buf, ks, 0, full); // in-place
                out.write(buf, 0, full);
            }

            if (rem != 0) System.arraycopy(buf, full, carry, 0, rem);
            carryLen = rem;
        }

        // Final PKCS#7 pad + encrypt
        byte[] last = new byte[carryLen];
        if (carryLen != 0) System.arraycopy(carry, 0, last, 0, carryLen);
        byte[] padded = Padding.padPKCS7(last);

        ECB.ecbProcessBlocks(AES.ENCRYPT_MODE, padded, ks);
        out.write(padded);
    }

    public static void decryptIStoOS(InputStream in, OutputStream out, KeySchedule ks) throws IOException {
        int bufSize = BUF & ~(BLOCK - 1);
        decryptIStoOS(in, out, ks,bufSize);
    }

    private static void decryptIStoOS(InputStream in, OutputStream out, KeySchedule ks, int bufSize) throws IOException {
        byte[] buf   = new byte[bufSize];
        byte[] carry = new byte[BLOCK]; // at most 15 bytes used
        int carryLen = 0;

        byte[] lastPlain = new byte[BLOCK];
        boolean hasLast = false;

        while (true) {
            if (carryLen != 0) System.arraycopy(carry, 0, buf, 0, carryLen);

            int n = in.read(buf, carryLen, buf.length - carryLen);
            if (n == -1) break;

            int total = carryLen + n;
            int full  = total & ~(BLOCK - 1);
            int rem   = total - full;

            if (full != 0) {
                // Decrypt full blocks in-place
                ECB.ecbProcessBlocks(AES.DECRYPT_MODE, buf, ks, 0, full);

                // Write all but the last block (keep last for final unpad)
                if (!hasLast) {
                    if (full == BLOCK) {
                        System.arraycopy(buf, 0, lastPlain, 0, BLOCK);
                        hasLast = true;
                    } else {
                        int writeLen = full - BLOCK;
                        out.write(buf, 0, writeLen);
                        System.arraycopy(buf, writeLen, lastPlain, 0, BLOCK);
                        hasLast = true;
                    }
                } else {
                    out.write(lastPlain, 0, BLOCK);
                    if (full == BLOCK) {
                        System.arraycopy(buf, 0, lastPlain, 0, BLOCK);
                    } else {
                        int writeLen = full - BLOCK;
                        out.write(buf, 0, writeLen);
                        System.arraycopy(buf, writeLen, lastPlain, 0, BLOCK);
                    }
                }
            }

            if (rem != 0) System.arraycopy(buf, full, carry, 0, rem);
            carryLen = rem;
        }

        if (carryLen != 0) throw new IOException("Ciphertext not block aligned");
        if (!hasLast) throw new IOException("Empty ciphertext");

        byte[] unpadded = Padding.unpadPKCS7(lastPlain);
        out.write(unpadded);
    }
}
