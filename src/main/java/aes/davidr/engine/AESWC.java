package aes.davidr.engine;

public class AESWC {
    private static final boolean AVAILABLE;

    static {
        boolean loaded;
        try {
            System.loadLibrary("aesni");
            loaded = true;
        } catch (UnsatisfiedLinkError e) {
            loaded = false;
        }
        AVAILABLE = loaded;
    }

    private static native void encryptBlock(byte[] in, byte[] expandedKeys, int rounds, int offset);
    private static native void decryptBlock(byte[] in, byte[] expandedKeys, int rounds, int offset);
    private static native void encryptBlocks(byte[] in, byte[] expandedKeys, int rounds, int offset, int len);
    private static native void decryptBlocks(byte[] in, byte[] expandedKeys, int rounds, int offset, int len);

    static boolean isAvailable() {
        return AVAILABLE;
    }

    private static byte[] crypt(byte[] in, KeySchedule ks, int offset) {

        int rounds = ks.getNr();

        encryptBlock(in, ksToArray(ks), rounds, offset);

        return in;
    }

    private static byte[] decrypt(byte[] in, KeySchedule ks, int offset) {

        int rounds = ks.getNr();
        
        decryptBlock(in, ksToArray(ks), rounds, offset);

        return in;
    }

    private static byte[] ksToArray(KeySchedule ks){
        int rounds = ks.getNr();
        byte[] keys = new byte[(rounds + 1) * 16];

        for (int r = 0; r <= rounds; r++) {
            System.arraycopy(ks.roundKey(r), 0, keys, r * 16, 16);
        }

        return keys;
    }

    public static byte[] ccrypt(boolean mode, byte[] s, KeySchedule ks, int offset){
        return mode ? crypt(s, ks, offset) : decrypt(s, ks, offset);
    }

    public static void ccryptBlocks(boolean mode, byte[] s, KeySchedule ks, int offset, int len) {
        int rounds = ks.getNr();
        byte[] expandedKeys = ksToArray(ks);

        if (mode) {
            encryptBlocks(s, expandedKeys, rounds, offset, len);
        } else {
            decryptBlocks(s, expandedKeys, rounds, offset, len);
        }
    }

}
