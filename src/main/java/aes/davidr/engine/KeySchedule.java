package aes.davidr.engine;

import java.nio.charset.StandardCharsets;

public class KeySchedule {

    private final int Nk; // 4 / 6 / 8
    private final int Nr; // 10 / 12 / 14
    private final int[] w; // expanded words: 4*(Nr+1)
    private final byte[][] roundKeyCache; // [Nr+1][16]

    public static final int AES_128 = 16;
    public static final int AES_192 = 24;
    public static final int AES_256 = 32;

    public KeySchedule(String textKey, int mode) {
        this(textKey.getBytes(StandardCharsets.UTF_8), mode);
    }

    public KeySchedule(String textKey) {
        this(textKey.getBytes(StandardCharsets.UTF_8), AES_128);
    }

    public KeySchedule(byte[] key, int mode) {
        this(deriveKey(key, mode));
    }

    private static byte[] deriveKey(byte[] key, int mode) {
        if (mode != AES_128 && mode != AES_192 && mode != AES_256)
            throw new IllegalArgumentException("not a mode");

        try {
            byte[] hash = java.security.MessageDigest.getInstance("SHA-256").digest(key); // 32 bytes
            return java.util.Arrays.copyOf(hash, mode); // mode is 16/24/32
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public KeySchedule(byte[] key) {
        if (key == null)
            throw new IllegalArgumentException("key must be 16/24/32 bytes");

        int len = key.length;

        if (len != 16 && len != 24 && len != 32)
            throw new IllegalArgumentException("key must be 16/24/32 bytes");

        this.Nk = len / 4; // Number of original Key words
        this.Nr = (Nk == 4) ? 10 : (Nk == 6 ? 12 : 14); // Number of AES Rounds
        int totalWords = 4 * (Nr + 1); // Number of round keys to be generated
        this.w = new int[totalWords];

        for (int i = 0; i < Nk; i++)
            w[i] = packWord(key, 4 * i);

        for (int i = Nk; i < totalWords; i++) {
            int t = w[i - 1];
            if (i % Nk == 0) {
                t = subWord(rotWord(t)) ^ rcon(i / Nk);
            } else if (Nk == 8 && (i % 8) == 4) { // AES-256 extra subWord
                t = subWord(t);
            }
            w[i] = w[i - Nk] ^ t;
        }

        roundKeyCache = new byte[Nr + 1][16];
        for (int r = 0; r <= Nr; r++) {
            int o = 4 * r;
            byte[] key1 = roundKeyCache[r];
            for (int c = 0; c < 4; c++) {
                int word = w[o + c];
                int base = (c << 2); // col*4
                key1[base] = (byte) (word >>> 24);
                key1[base + 1] = (byte) (word >>> 16);
                key1[base + 2] = (byte) (word >>> 8);
                key1[base + 3] = (byte) (word);
            }
        }

    }

    public int getNr() {
        return Nr;
    }

    public byte[] roundKey(int r) {
        if (r < 0 || r > Nr)
            throw new IllegalArgumentException("round 0 to " + Nr);
        return roundKeyCache[r];
    }

    private static int s(int idx) { // Tables.S is byte[]
        return (Tables.S[idx & 0xFF]) & 0xFF;
    }

    private static int rotWord(int x) { // rotate left by one byte
        return (x << 8) | ((x >>> 24) & 0xFF);
    }

    private static int subWord(int x) {
        int b0 = s((x >>> 24)); // top byte of x: 0xXX000000
        int b1 = s((x >>> 16)); // next byte: 0x00XX0000
        int b2 = s((x >>> 8)); // next byte: 0x0000XX00
        int b3 = s(x & 0xFF); // lowest byte: 0x000000XX
        return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
    }

    private static int rcon(int j) {
        return (Tables.rcon[j - 1] & 0xFF) << 24;
    }

    private static int packWord(byte[] s, int off) {
        int a = (s[off] & 0xFF) << 24; // top 8 bits
        int b = (s[off + 1] & 0xFF) << 16; // next 8 bits
        int c = (s[off + 2] & 0xFF) << 8; // next 8 bits
        int d = (s[off + 3] & 0xFF); // lowest 8 bits

        int word = a | b | c | d;

        return word;
    }

}