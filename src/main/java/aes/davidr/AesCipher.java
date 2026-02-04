package aes.davidr;

import java.io.File;
import java.io.IOException;

import aes.davidr.engine.KeySchedule;
import aes.davidr.fileCrypto.FileECB;
import aes.davidr.modes.ECB;

public final class AesCipher {
    public static final int AES_128 = KeySchedule.AES_128;
    public static final int AES_192 = KeySchedule.AES_192;
    public static final int AES_256 = KeySchedule.AES_256;
    public static final boolean ENCRYPT_MODE = true;
    public static final boolean DECRYPT_MODE = false;


    public static byte[] cryptBytes(boolean encrypt, byte[] in, String key) {
        return cryptBytes(encrypt, in, key, AES_128);
    }

    public static byte[] cryptBytes(boolean encrypt, byte[] in, byte[] key) {
        return ECB.ecbCryptBytes(encrypt, in, keyScheduleForBytes(key));
    }

    public static byte[] cryptBytes(boolean encrypt, byte[] in, String key, int mode) {
        return ECB.ecbCryptBytes(encrypt, in, new KeySchedule(key, mode));
    }

    public static byte[] cryptBytes(boolean encrypt, byte[] in, byte[] key, int mode) {
        return ECB.ecbCryptBytes(encrypt, in, new KeySchedule(key, mode));
    }

    public static void cryptFile(boolean encrypt, File inFile, File outFile, String key) throws IOException {
        cryptFile(encrypt, inFile, outFile, key, AES_128);
    }

    public static void cryptFile(boolean encrypt, File inFile, File outFile, byte[] key) throws IOException {
        FileECB.processFile(encrypt, inFile, outFile, keyScheduleForBytes(key));
    }

    public static void cryptFile(boolean encrypt, File inFile, File outFile, String key, int mode) throws IOException {
        FileECB.processFile(encrypt, inFile, outFile, new KeySchedule(key, mode));
    }

    public static void cryptFile(boolean encrypt, File inFile, File outFile, byte[] key, int mode) throws IOException {
        FileECB.processFile(encrypt, inFile, outFile, new KeySchedule(key, mode));
    }

    private static KeySchedule keyScheduleForBytes(byte[] key) {
        if (key == null)
            throw new IllegalArgumentException("key is null");
        int len = key.length;
        if (len == 16 || len == 24 || len == 32)
            return new KeySchedule(key);
        return new KeySchedule(key, AES_128);
    }
}
