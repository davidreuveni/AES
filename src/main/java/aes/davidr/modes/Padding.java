package aes.davidr.modes;

public class Padding {

    public static byte[] PKCS7(boolean mode, byte[] data){
        return mode ? padPKCS7(data) : unpadPKCS7(data);
    }

    public static byte[] padPKCS7(byte[] data) {
        if (data == null) {
            throw new NullPointerException("no PKCS#7 padding input");
        }
        int blockSize = 16;
        int padLen = blockSize - (data.length % blockSize);

        byte[] padded = new byte[data.length + padLen];
        // copy original bytes
        for (int i = 0; i < data.length; i++) {
            padded[i] = data[i];
        }
        // add padding bytes
        for (int i = data.length; i < padded.length; i++) {
            padded[i] = (byte) padLen;
        }
        return padded;
    }

    public static byte[] unpadPKCS7(byte[] data) {
        if (data == null) throw new NullPointerException("data is missing");
        if(data.length == 0)throw new IllegalArgumentException("empty input");
        int padLen = data[data.length - 1] & 0xFF;
        for (int i = 1; i < padLen + 1; i++) {
            if ((data[data.length - i] & 0xFF) != padLen)
                throw new IllegalArgumentException("Bad PKCS#7 padding");
        }
        byte[] unpadded = new byte[data.length - padLen];
        for (int i = 0; i < unpadded.length; i++) {
            unpadded[i] = data[i];
        }
        return unpadded;

    }

}
