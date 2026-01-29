package aes.davidr.engine;

public class GaloisField {
    private static byte xtime(byte b) {
        int x = b & 0xFF;
        int r = x << 1;
        if ((x & 0x80) != 0)
            r ^= 0x1B; // reduce modulo x^8 + x^4 + x^3 + x + 1
        return (byte) (r & 0xFF);
    }

    public static byte mul2(byte b) {
        return xtime(b);
    }

    public static byte mul3(byte b) {
        return (byte) ((mul2(b) ^ b) & 0xFF);
    }

    public static byte mul4(byte b) {
        byte mul4 = mul2(mul2(b));
        return (byte) (mul4 & 0xFF);
    }

    public static byte mul8(byte b) {
        return mul2(mul4(b));
    }

    @Deprecated
    public static byte mul09(byte b) {
        return (byte) (((mul8(b) ^ b) & 0xFF) & 0xFF);
    }

    @Deprecated
    public static byte mul11(byte b) {
        return (byte) (((mul8(b) ^ mul2(b)) ^ b) & 0xFF);
    }

    @Deprecated
    public static byte mul13(byte b) {
        return (byte) (((mul8(b) ^ mul4(b)) ^ b) & 0xFF);
    }

    @Deprecated
    public static byte mul14(byte b) {
        return (byte) (((mul8(b) ^ mul4(b)) ^ mul2(b)) & 0xFF);
    }
}
