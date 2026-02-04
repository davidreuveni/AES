# AES Engine

This project is a small, self-contained Java AES implementation focused on a simple public API. It is intended for learning and basic utility use, with a clear, minimal surface area for encryption/decryption of byte arrays and files.

If you only need to encrypt or decrypt data, use `aes.davidr.AesCipher`. The rest of the codebase contains lower-level primitives and helpers.

## Public API

All public entry points are in `aes.davidr.AesCipher` and provide ECB mode with PKCS#7 padding.

### Constants

- `AesCipher.AES_128`, `AesCipher.AES_192`, `AesCipher.AES_256`

### Byte arrays

```java
import aes.davidr.AesCipher;

byte[] data = "hello".getBytes(java.nio.charset.StandardCharsets.UTF_8);

// default AES-128, key derived from string
byte[] encrypted = AesCipher.cryptBytes(AesCipher.ENCRYPT_MODE, data, "my passphrase");
byte[] decrypted = AesCipher.cryptBytes(AesCipher.DECRYPT_MODE, encrypted, "my passphrase");

// explicit key size (AES-256)
byte[] encrypted256 = AesCipher.cryptBytes(AesCipher.ENCRYPT_MODE, data, "my passphrase", AesCipher.AES_256);

// raw key bytes: if length is 16/24/32 it's used directly; otherwise it is derived as AES-128
byte[] rawKey = new byte[16];
byte[] encryptedRaw = AesCipher.cryptBytes(AesCipher.ENCRYPT_MODE, data, rawKey);
```

### Files

```java
import aes.davidr.AesCipher;
import java.io.File;

File in = new File("plain.bin");
File enc = new File("plain.bin.enc");
File dec = new File("plain.bin.dec");

AesCipher.cryptFile(AesCipher.ENCRYPT_MODE, in, enc, "my passphrase");
AesCipher.cryptFile(AesCipher.DECRYPT_MODE, enc, dec, "my passphrase");

// explicit key size (AES-192)
AesCipher.cryptFile(AesCipher.ENCRYPT_MODE, in, enc, "my passphrase", AesCipher.AES_192);
```

## Notes

- String keys are derived via SHA-256 and truncated to the selected AES key size.
- Byte[] keys of length 16/24/32 are treated as raw AES keys; other lengths are derived as AES-128.
- File operations stream data with PKCS#7 padding.

## Build & test

This is a Maven project. To compile and run tests:

```bash
mvn test
```

To build the jar without running tests:

```bash
mvn -DskipTests package
```
