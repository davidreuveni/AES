# AES Engine

A small Java AES implementation with supporting utilities for ECB mode, PKCS#7 padding, file encryption, and optional HMAC integrity checks. The project includes a Maven build and unit tests for core primitives.

## Features

- AES block cipher implementation with key expansion.
- ECB mode block processing with PKCS#7 padding helpers.
- File encryption/decryption helpers (streamed, block-aligned).
- Optional file format with HMAC-SHA256 integrity tags.

## Project layout

- `src/main/java/aes/davidr/engine`: Core AES primitives (S-box tables, Galois field ops, key schedule, block cipher).
- `src/main/java/aes/davidr/modes`: ECB mode and padding utilities.
- `src/main/java/aes/davidr/fileCrypto`: File encryption helpers and HMAC wrapper.
- `src/test/java`: Unit tests and small benchmark/utility classes.

## Build & test

This is a Maven project. To compile and run tests:

```bash
mvn test
```

To build the jar without running tests:

```bash
mvn -DskipTests package
```

## Usage examples

### Encrypt/decrypt a byte array with ECB

```java
KeySchedule ks = new KeySchedule("my passphrase");
byte[] data = "hello world".getBytes(java.nio.charset.StandardCharsets.UTF_8);

byte[] padded = aes.davidr.modes.Padding.padPKCS7(data);
ECB.ecbProcessBlocks(aes.davidr.engine.AES.ENCRYPT_MODE, padded, ks);

ECB.ecbProcessBlocks(aes.davidr.engine.AES.DECRYPT_MODE, padded, ks);
byte[] plain = aes.davidr.modes.Padding.unpadPKCS7(padded);
```
when using string as input to the keyschdual it will hash it and use the hash as te key to use an actual key pass in a byte aray

### Encrypt/decrypt files (ECB + PKCS#7)

```java
import aes.davidr.engine.KeySchedule;
import aes.davidr.fileCrypto.FileECB;

KeySchedule ks = new KeySchedule("my passphrase");
FileECB.processFile(FileECB.ENCRYPT_MODE, new java.io.File("plain.bin"), new java.io.File("plain.bin.enc"), ks);
FileECB.processFile(FileECB.DECRYPT_MODE, new java.io.File("plain.bin.enc"), new java.io.File("plain.bin.dec"), ks);
```

### Encrypt/decrypt files with HMAC integrity

```java
import aes.davidr.fileCrypto.HMAC;

byte[] key = "my passphrase".getBytes(java.nio.charset.StandardCharsets.UTF_8);
HMAC.processFile(HMAC.ENCRYPT_MODE, new java.io.File("plain.bin"), new java.io.File("plain.bin.enc"), key);
HMAC.processFile(HMAC.DECRYPT_MODE, new java.io.File("plain.bin.enc"), new java.io.File("plain.bin.dec"), key);
```

## Notes

- `KeySchedule` accepts 16/24/32-byte keys for AES-128/192/256. When constructed from a string, the key is derived via SHA-256 and truncated to the chosen key size.
- The file helpers buffer data in memory but stream the encryption/decryption process for large files.
