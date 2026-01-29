package aes.davidr.modes;

import java.util.Arrays;

import aes.davidr.engine.AES;
import aes.davidr.engine.KeySchedule;

public final class ECB {
    private static final int BLOCK = 16;

    private ECB() {
    }

    /** In-place single-block ECB (fast, minimal checks). */
    public static byte[] ecbProcessBlock(boolean mode, byte[] in, KeySchedule ks, int offset) {
        if (in == null || ks == null)
            throw new IllegalArgumentException("null");
        if (offset < 0 || offset + BLOCK > in.length)
            throw new IllegalArgumentException("bad offset");
        return AES.blockRun(mode, in, ks, offset); // in-place
    }

    /**
     * In-place bulk ECB: process len bytes from offset. len MUST be multiple of 16.
     */
    public static void ecbProcessBlocks(boolean mode, byte[] in, KeySchedule ks, int offset, int len) {
        if (in == null || ks == null)
            throw new IllegalArgumentException("null");
        if ((offset | len) < 0 || offset + len > in.length)
            throw new IllegalArgumentException("bad range");
        if ((len & (BLOCK - 1)) != 0) // if len is multiple of 16, its last 4 bits are 0 len & 15 will be 0 only for
                                      // multiples of 16
            throw new IllegalArgumentException("len must be multiple of 16");
        for (int off = offset; off < (offset + len); off += BLOCK) {
            AES.blockRun(mode, in, ks, off);
        }
    }

    private static byte[] ecbEncryptAny(byte[] plaintext, KeySchedule ks) {
        if (plaintext == null || ks == null)
            throw new IllegalArgumentException("null");

        byte[] padded = Padding.PKCS7(true, plaintext);
        ECB.ecbProcessBlocks(true, padded, ks); 
        return padded;
    }

    private static byte[] ecbDecryptAny(byte[] ciphertext, KeySchedule ks) {
        if (ciphertext == null || ks == null)
            throw new IllegalArgumentException("null");
        if ((ciphertext.length & 15) != 0)
            throw new IllegalArgumentException("ciphertext must be multiple of 16");

        byte[] buf = Arrays.copyOf(ciphertext, ciphertext.length); 
        ECB.ecbProcessBlocks(false, buf, ks); 
        return Padding.PKCS7(false, buf);
    }

    public static byte[] ecbCryptBytes(boolean mode, byte[] in, KeySchedule ks){
        return mode ? ecbEncryptAny(in, ks) : ecbDecryptAny(in, ks);
    }

    /** Convenience: in-place bulk ECB over whole array. */
    public static void ecbProcessBlocks(boolean mode, byte[] in, KeySchedule ks) {
        ecbProcessBlocks(mode, in, ks, 0, in.length);
    }
}
