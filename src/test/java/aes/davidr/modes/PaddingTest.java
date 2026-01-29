package aes.davidr.modes;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import org.junit.jupiter.api.Test;

public class PaddingTest {
    @Test
    void testPadPKCS7NormalInput() {
        byte[] data = {
                0x00, 0x01, 0x02, 0x03,
                0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B,
                0x0C, 0x0D
        };

        byte[] padded = {
                0x00, 0x01, 0x02, 0x03,
                0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B,
                0x0C, 0x0D, 0x02, 0x02
        };

        assertArrayEquals(padded, Padding.padPKCS7(data));

    }

    @Test
    void testUnpadPKCS7NormalInput() {
        byte[] data = {
                0x00, 0x01, 0x02, 0x03,
                0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B,
                0x0C, 0x0D
        };

        byte[] padded = {
                0x00, 0x01, 0x02, 0x03,
                0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B,
                0x0C, 0x0D, 0x02, 0x02
        };

        byte[] padded6 = {
                0x00, 0x01, 0x02, 0x03,
                0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x06, 0x06,
                0x06, 0x06, 0x06, 0x06
        };
        assertArrayEquals(data, Padding.unpadPKCS7(padded));
        assertEquals(10, Padding.unpadPKCS7(padded6).length);
    }

    @Test
    void testUnpadPKCS7WrongInput() {
        byte[] data = {
                0x00, 0x01, 0x02, 0x03,
                0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B,
                0x0C, 0x0D
        };
        byte[] paddedW = {
                0x00, 0x01, 0x02, 0x03,
                0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B,
                0x0C, 0x0D, 0x01, 0x02
        };
        byte[] empty = {};

        assertThrows(IllegalArgumentException.class, () -> Padding.unpadPKCS7(paddedW));
        assertThrows(IllegalArgumentException.class, () -> Padding.unpadPKCS7(data));
        assertThrows(IllegalArgumentException.class, () -> Padding.unpadPKCS7(empty));
    }

    @Test
    void testpadPKCS7WrongInput() {
        byte[] full = {
                0x00, 0x01, 0x02, 0x03,
                0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B,
                0x0C, 0x0D, 0x0E, 0x0F
        };
        byte[] empty = {};

        assertEquals(32, Padding.padPKCS7(full).length);
        assertEquals(16, Padding.padPKCS7(empty).length);
    }

    @Test
    void testPKCS7NullInput() {
        byte[] paddedN = null;
        assertThrows(NullPointerException.class, () -> Padding.padPKCS7(paddedN));
        assertThrows(NullPointerException.class, () -> Padding.unpadPKCS7(paddedN));
    }
}
