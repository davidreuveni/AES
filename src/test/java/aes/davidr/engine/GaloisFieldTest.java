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
    
    @Test
    public void testMul4() {
        assertEquals((byte) 0x00, GaloisField.mul4((byte) 0x00));
        assertEquals((byte) 0x04, GaloisField.mul4((byte) 0x01));
        assertEquals((byte) 0x08, GaloisField.mul4((byte) 0x02));
    }
    
    @Test
    public void testMul8() {
        assertEquals((byte) 0x00, GaloisField.mul8((byte) 0x00));
        assertEquals((byte) 0x08, GaloisField.mul8((byte) 0x01));
        assertEquals((byte) 0x10, GaloisField.mul8((byte) 0x02));
    }
    
    @Test
    public void testMul09() {
        assertEquals((byte) 0x00, GaloisField.mul09((byte) 0x00));
        assertEquals((byte) 0x09, GaloisField.mul09((byte) 0x01));
        assertEquals((byte) 0x12, GaloisField.mul09((byte) 0x02));
    }
    
    @Test
    public void testMul11() {
        assertEquals((byte) 0x00, GaloisField.mul11((byte) 0x00));
        assertEquals((byte) 0x0B, GaloisField.mul11((byte) 0x01));
        assertEquals((byte) 0x16, GaloisField.mul11((byte) 0x02));
    }
    
    @Test
    public void testMul13() {
        assertEquals((byte) 0x00, GaloisField.mul13((byte) 0x00));
        assertEquals((byte) 0x0D, GaloisField.mul13((byte) 0x01));
        assertEquals((byte) 0x1A, GaloisField.mul13((byte) 0x02));
    }
    
    @Test
    public void testMul14() {
        assertEquals((byte) 0x00, GaloisField.mul14((byte) 0x00));
        assertEquals((byte) 0x0E, GaloisField.mul14((byte) 0x01));
        assertEquals((byte) 0x1C, GaloisField.mul14((byte) 0x02));
    }
}