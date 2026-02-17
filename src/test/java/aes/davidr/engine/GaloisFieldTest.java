package aes.davidr.engine;

import org.junit.Test;
import static org.junit.Assert.*;


public class GaloisFieldTest {
    
    @Test
    public void testMul2() {
        assertEquals((byte) 0x00, GaloisField.mul2((byte) 0x00));
        assertEquals((byte) 0x02, GaloisField.mul2((byte) 0x01));
        assertEquals((byte) 0x04, GaloisField.mul2((byte) 0x02));
    }
    
    @Test
    public void testMul3() {
        assertEquals((byte) 0x00, GaloisField.mul3((byte) 0x00));
        assertEquals((byte) 0x03, GaloisField.mul3((byte) 0x01));
        assertEquals((byte) 0x06, GaloisField.mul3((byte) 0x02));
    }
}