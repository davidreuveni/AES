package aes.davidr.engine;

public class AES {

    // - constants -
    // ---------------------------------------
    public static final boolean ENCRYPT_MODE = true;
    public static final boolean DECRYPT_MODE = false;
    private static final int BLOCK_LENGTH = 16;

    // ---------------------------------------
    // - helpers -
    // ---------------------------------------
    private static int idx(int row, int col) {
        return (col << 2) | row; // col*4 + row (bit shift faster)
    }

    private static byte get(byte[] s, int row, int col, int off) {
        return s[idx(row, col) + off];
    }

    private static void set(byte[] s, int row, int col, byte v, int off) {
        s[idx(row, col) + off] = v;
    }
    // ---------------------------------------

    static void subBytes(byte[] s, int off) {
        for (int i = off; i < BLOCK_LENGTH + off; i++) {
            s[i] = Tables.S[s[i] & 0xFF];
        }
    }

    static void invSubBytes(byte[] s, int off) {
        for (int i = off; i < BLOCK_LENGTH + off; i++) {
            s[i] = Tables.Si[s[i] & 0xFF];
        }
    }

    static void shiftRows(byte[] s, int off) {
        byte tmp;

        // Row 1
        tmp = get(s, 1, 0, off);
        set(s, 1, 0, get(s, 1, 1, off), off);
        set(s, 1, 1, get(s, 1, 2, off), off);
        set(s, 1, 2, get(s, 1, 3, off), off);
        set(s, 1, 3, tmp, off);

        // Row 2
        tmp = get(s, 2, 0, off);
        set(s, 2, 0, get(s, 2, 2, off), off);
        set(s, 2, 2, tmp, off);
        tmp = get(s, 2, 1, off);
        set(s, 2, 1, get(s, 2, 3, off), off);
        set(s, 2, 3, tmp, off);

        // Row 3
        tmp = get(s, 3, 3, off);
        set(s, 3, 3, get(s, 3, 2, off), off);
        set(s, 3, 2, get(s, 3, 1, off), off);
        set(s, 3, 1, get(s, 3, 0, off), off);
        set(s, 3, 0, tmp, off);

    }

    static void invShiftRows(byte[] s, int off) {
        byte tmp;

        // Row 1
        tmp = get(s, 1, 3, off);
        set(s, 1, 3, get(s, 1, 2, off), off);
        set(s, 1, 2, get(s, 1, 1, off), off);
        set(s, 1, 1, get(s, 1, 0, off), off);
        set(s, 1, 0, tmp, off);

        // Row 2
        tmp = get(s, 2, 0, off);
        set(s, 2, 0, get(s, 2, 2, off), off);
        set(s, 2, 2, tmp, off);
        tmp = get(s, 2, 1, off);
        set(s, 2, 1, get(s, 2, 3, off), off);
        set(s, 2, 3, tmp, off);

        // Row 3
        tmp = get(s, 3, 0, off);
        set(s, 3, 0, get(s, 3, 1, off), off);
        set(s, 3, 1, get(s, 3, 2, off), off);
        set(s, 3, 2, get(s, 3, 3, off), off);
        set(s, 3, 3, tmp, off);

}

    static void xorRoundKey(byte[] s, byte[] k, int off) {
        for (int j = 0; j < BLOCK_LENGTH; j++) {
            s[off + j] ^= k[j];
        }
    }

    static void mixColumns(byte[] s, int off) {
        for (int c = 0; c < 4; c++) {
            byte s0 = get(s, 0, c, off);
            byte s1 = get(s, 1, c, off);
            byte s2 = get(s, 2, c, off);
            byte s3 = get(s, 3, c, off);

            byte r0 = (byte) ((GaloisField.mul2(s0) ^ GaloisField.mul3(s1) ^ s2 ^ s3) & 0xFF);
            byte r1 = (byte) ((s0 ^ GaloisField.mul2(s1) ^ GaloisField.mul3(s2) ^ s3) & 0xFF);
            byte r2 = (byte) ((s0 ^ s1 ^ GaloisField.mul2(s2) ^ GaloisField.mul3(s3)) & 0xFF);
            byte r3 = (byte) ((GaloisField.mul3(s0) ^ s1 ^ s2 ^ GaloisField.mul2(s3)) & 0xFF);

            set(s, 0, c, r0, off);
            set(s, 1, c, r1, off);
            set(s, 2, c, r2, off);
            set(s, 3, c, r3, off);
        }
    }

    static void invMixColumns(byte[] s, int off) {
        for (int c = 0; c < 4; c++) {
            byte s0 = get(s, 0, c, off);
            byte s1 = get(s, 1, c, off);
            byte s2 = get(s, 2, c, off);
            byte s3 = get(s, 3, c, off);

            byte r0 = (byte) ((Tables.MUL_14[s0 & 0xFF] ^ Tables.MUL_11[s1 & 0xFF] ^ Tables.MUL_13[s2 & 0xFF]
                    ^ Tables.MUL_09[s3 & 0xFF]) & 0xFF);

            byte r1 = (byte) ((Tables.MUL_09[s0 & 0xFF] ^ Tables.MUL_14[s1 & 0xFF] ^ Tables.MUL_11[s2 & 0xFF]
                    ^ Tables.MUL_13[s3 & 0xFF]) & 0xFF);

            byte r2 = (byte) ((Tables.MUL_13[s0 & 0xFF] ^ Tables.MUL_09[s1 & 0xFF] ^ Tables.MUL_14[s2 & 0xFF]
                    ^ Tables.MUL_11[s3 & 0xFF]) & 0xFF);

            byte r3 = (byte) ((Tables.MUL_11[s0 & 0xFF] ^ Tables.MUL_13[s1 & 0xFF] ^ Tables.MUL_09[s2 & 0xFF]
                    ^ Tables.MUL_14[s3 & 0xFF]) & 0xFF);

            set(s, 0, c, r0, off);
            set(s, 1, c, r1, off);
            set(s, 2, c, r2, off);
            set(s, 3, c, r3, off);
        }
    }

    private static byte[] cryptBlock(byte[] s, KeySchedule ks, int off) {

        int n = ks.getNr();

        xorRoundKey(s, ks.roundKey(0), off);

        for (int i = 1; i < n; i++) {
            subBytes(s, off);
            shiftRows(s, off);
            mixColumns(s, off);
            xorRoundKey(s, ks.roundKey(i), off);
        }
        subBytes(s, off);
        shiftRows(s, off);
        xorRoundKey(s, ks.roundKey(n), off);

        return s;
    }

    private static byte[] decryptBlock(byte[] s, KeySchedule ks, int off) {

        int n = ks.getNr();

        xorRoundKey(s, ks.roundKey(n), off);

        for (int i = n - 1; i >= 1; i--) {
            invShiftRows(s, off);
            invSubBytes(s, off);
            xorRoundKey(s, ks.roundKey(i), off);
            invMixColumns(s, off);

        }
        invShiftRows(s, off);
        invSubBytes(s, off);
        xorRoundKey(s, ks.roundKey(0), off);

        return s;
    }

    public static byte[] blockRun(boolean mode, byte[] s, KeySchedule ks, int off) {
        return mode ? cryptBlock(s, ks, off) : decryptBlock(s, ks, off);
    }

    public static byte[] blockRun(boolean mode, byte[] s, KeySchedule ks) {
        return blockRun(mode, s, ks, 0);
    }

}