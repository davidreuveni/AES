package aes.davidr.nonTestsTests;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;

import aes.davidr.engine.KeySchedule;
import aes.davidr.fileCrypto.FileECB;

public class EncryptFile {
    public static void main(String[] args) throws IOException {
        String path = "src\\test\\java\\aes\\davidr\\test.jpg";
        encryptFileAndPlaceOnDesktop(path);
    }
    public static void encryptFileAndPlaceOnDesktop(String pathString) throws IOException{
        byte[] key = {
                0x00, 0x01, 0x02, 0x03,
                0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B,
                0x0C, 0x0D, 0x0E, 0x0F
        };

        // key in hex is: /000102030405060708090A0B0C0D0E0F/
        // key in plain text (Base64) is: /AAECAwQFBgcICQoLDA0ODw==/
        KeySchedule ks = new KeySchedule(key);

        // 1) Preferred file path (your original)
        Path path = Paths.get(pathString);
        String fileName = path.getFileName().toString();

        Path tempDir = Files.createTempDirectory("aes-benchmark");
        Path plain = tempDir.resolve("test.d");
        Path enc   = tempDir.resolve("test.d.enc");

        Files.copy(path, plain, StandardCopyOption.REPLACE_EXISTING);

        FileECB.processFile(FileECB.ENCRYPT_MODE, plain.toFile(), enc.toFile(), ks);

        String outPath = "C:\\Users\\reuve\\Desktop\\"+fileName;
        Files.copy(enc, Paths.get(outPath), StandardCopyOption.REPLACE_EXISTING);
    }
}
