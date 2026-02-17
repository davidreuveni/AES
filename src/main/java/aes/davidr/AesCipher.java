package aes.davidr;

import java.io.File;
import java.io.IOException;

import aes.davidr.engine.KeySchedule;
import aes.davidr.fileCrypto.FileECB;
import aes.davidr.modes.ECB;

/**
 * Public-facing AES API for byte-array and file encryption/decryption operations.
 * This class provides static convenience methods that wrap key scheduling and ECB processing internals.
 * Use {@link #ENCRYPT_MODE}/{@link #DECRYPT_MODE} for operation direction and
 * {@link #AES_128}, {@link #AES_192}, or {@link #AES_256} to choose key size mode.
 * Main entry points are {@link #cryptBytes(boolean, byte[], String)} for in-memory data and
 * {@link #cryptFile(boolean, File, File, String)} for file input/output.
 * Both methods are overloaded and accept either a {@code String} key or {@code byte[]} key.
 * Typical usage: pass {@link #ENCRYPT_MODE} or {@link #DECRYPT_MODE}, provide input plus key,
 * and optionally use overloads with an explicit AES mode constant.
 */
public final class AesCipher {
    public static final int AES_128 = KeySchedule.AES_128;
    public static final int AES_192 = KeySchedule.AES_192;
    public static final int AES_256 = KeySchedule.AES_256;
    public static final boolean ENCRYPT_MODE = true;
    public static final boolean DECRYPT_MODE = false;

    /**
     * Processes a byte array with AES in ECB mode using a string key.
     * This overload always uses AES-128 by default and delegates to the mode-aware method.
     * Use {@link #ENCRYPT_MODE} for encryption and {@link #DECRYPT_MODE} for decryption.
     *
     * @param encrypt use {@link #ENCRYPT_MODE} to encrypt or {@link #DECRYPT_MODE} to decrypt
     * @param in input bytes to process
     * @param key key text used to build the AES key schedule
     * @return processed bytes
     */
    public static byte[] cryptBytes(boolean encrypt, byte[] in, String key) {
        return cryptBytes(encrypt, in, key, AES_128);
    }

    /**
     * Processes a byte array with AES in ECB mode using raw key bytes.
     * Key length 16/24/32 selects AES-128/192/256 automatically via {@code keyScheduleForBytes}.
     * Other key lengths are normalized by falling back to AES-128 key scheduling.
     *
     * @param encrypt use {@link #ENCRYPT_MODE} to encrypt or {@link #DECRYPT_MODE} to decrypt
     * @param in input bytes to process
     * @param key raw key bytes
     * @return processed bytes
     */
    public static byte[] cryptBytes(boolean encrypt, byte[] in, byte[] key) {
        return ECB.ecbCryptBytes(encrypt, in, keyScheduleForBytes(key));
    }

    /**
     * Processes a byte array with AES in ECB mode using a string key and explicit key size mode.
     * The method creates a {@link KeySchedule} from the provided string and mode.
     * It then delegates block processing to {@link ECB#ecbCryptBytes(boolean, byte[], KeySchedule)}.
     *
     * @param encrypt use {@link #ENCRYPT_MODE} to encrypt or {@link #DECRYPT_MODE} to decrypt
     * @param in input bytes to process
     * @param key key text used to build the AES key schedule
     * @param mode key size mode ({@link #AES_128}, {@link #AES_192}, or {@link #AES_256})
     * @return processed bytes
     */
    public static byte[] cryptBytes(boolean encrypt, byte[] in, String key, int mode) {
        return ECB.ecbCryptBytes(encrypt, in, new KeySchedule(key, mode));
    }

    /**
     * Processes a byte array with AES in ECB mode using raw key bytes and explicit key size mode.
     * The given mode controls how the key is expanded, even when the raw key length differs.
     * Encryption/decryption work is delegated to the ECB byte processor.
     *
     * @param encrypt use {@link #ENCRYPT_MODE} to encrypt or {@link #DECRYPT_MODE} to decrypt
     * @param in input bytes to process
     * @param key raw key bytes
     * @param mode key size mode ({@link #AES_128}, {@link #AES_192}, or {@link #AES_256})
     * @return processed bytes
     */
    public static byte[] cryptBytes(boolean encrypt, byte[] in, byte[] key, int mode) {
        return ECB.ecbCryptBytes(encrypt, in, new KeySchedule(key, mode));
    }

    /**
     * Processes a file with AES in ECB mode using a string key.
     * This overload defaults to AES-128 and forwards to the mode-aware file method.
     * Input is read from {@code inFile} and result bytes are written to {@code outFile}.
     *
     * @param encrypt use {@link #ENCRYPT_MODE} to encrypt or {@link #DECRYPT_MODE} to decrypt
     * @param inFile input file
     * @param outFile output file
     * @param key key text used to build the AES key schedule
     * @throws IOException if reading or writing a file fails
     */
    public static void cryptFile(boolean encrypt, File inFile, File outFile, String key) throws IOException {
        cryptFile(encrypt, inFile, outFile, key, AES_128);
    }

    /**
     * Processes a file with AES in ECB mode using raw key bytes.
     * Key length 16/24/32 selects AES-128/192/256 automatically via {@code keyScheduleForBytes}.
     * File streaming and block handling are delegated to {@link FileECB#processFile}.
     *
     * @param encrypt use {@link #ENCRYPT_MODE} to encrypt or {@link #DECRYPT_MODE} to decrypt
     * @param inFile input file
     * @param outFile output file
     * @param key raw key bytes
     * @throws IOException if reading or writing a file fails
     */
    public static void cryptFile(boolean encrypt, File inFile, File outFile, byte[] key) throws IOException {
        FileECB.processFile(encrypt, inFile, outFile, keyScheduleForBytes(key));
    }

    /**
     * Processes a file with AES in ECB mode using a string key and explicit key size mode.
     * A {@link KeySchedule} is built from the key and mode before processing starts.
     * File input/output and ECB transformation are handled by {@link FileECB#processFile}.
     *
     * @param encrypt use {@link #ENCRYPT_MODE} to encrypt or {@link #DECRYPT_MODE} to decrypt
     * @param inFile input file
     * @param outFile output file
     * @param key key text used to build the AES key schedule
     * @param mode key size mode ({@link #AES_128}, {@link #AES_192}, or {@link #AES_256})
     * @throws IOException if reading or writing a file fails
     */
    public static void cryptFile(boolean encrypt, File inFile, File outFile, String key, int mode) throws IOException {
        FileECB.processFile(encrypt, inFile, outFile, new KeySchedule(key, mode));
    }

    /**
     * Processes a file with AES in ECB mode using raw key bytes and explicit key size mode.
     * The provided mode determines key expansion used during encryption or decryption.
     * Work is delegated to {@link FileECB#processFile} for file I/O and block processing.
     *
     * @param encrypt use {@link #ENCRYPT_MODE} to encrypt or {@link #DECRYPT_MODE} to decrypt
     * @param inFile input file
     * @param outFile output file
     * @param key raw key bytes
     * @param mode key size mode ({@link #AES_128}, {@link #AES_192}, or {@link #AES_256})
     * @throws IOException if reading or writing a file fails
     */
    public static void cryptFile(boolean encrypt, File inFile, File outFile, byte[] key, int mode) throws IOException {
        FileECB.processFile(encrypt, inFile, outFile, new KeySchedule(key, mode));
    }

    /**
     * Creates a {@link KeySchedule} from raw key bytes.
     * For 16/24/32-byte keys, the size directly maps to AES-128/192/256.
     * Any other non-null size falls back to AES-128 scheduling.
     *
     * @param key raw key bytes
     * @return key schedule for AES operations
     * @throws IllegalArgumentException if {@code key} is {@code null}
     */
    private static KeySchedule keyScheduleForBytes(byte[] key) {
        if (key == null)
            throw new IllegalArgumentException("key is null");
        int len = key.length;
        if (len == 16 || len == 24 || len == 32)
            return new KeySchedule(key);
        return new KeySchedule(key, AES_128);
    }
}


