#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <wmmintrin.h>

static void make_decrypt_keys(const uint8_t *ek, __m128i *dk, int rounds) {
    dk[0] = _mm_loadu_si128((const __m128i *)(ek + rounds * 16));

    for (int i = 1; i < rounds; i++) {
        __m128i k = _mm_loadu_si128((const __m128i *)(ek + (rounds - i) * 16));
        dk[i] = _mm_aesimc_si128(k);
    }

    dk[rounds] = _mm_loadu_si128((const __m128i *)(ek + 0));
}

static void encrypt_one(uint8_t *ptr, const uint8_t *key, int rounds) {
    __m128i block = _mm_loadu_si128((const __m128i *)ptr);

    block = _mm_xor_si128(block, _mm_loadu_si128((const __m128i *)(key + 0)));

    for (int r = 1; r < rounds; r++) {
        __m128i rk = _mm_loadu_si128((const __m128i *)(key + r * 16));
        block = _mm_aesenc_si128(block, rk);
    }

    block = _mm_aesenclast_si128(
        block,
        _mm_loadu_si128((const __m128i *)(key + rounds * 16))
    );

    _mm_storeu_si128((__m128i *)ptr, block);
}

static void decrypt_one(uint8_t *ptr, const __m128i *dk, int rounds) {
    __m128i block = _mm_loadu_si128((const __m128i *)ptr);

    block = _mm_xor_si128(block, dk[0]);

    for (int r = 1; r < rounds; r++) {
        block = _mm_aesdec_si128(block, dk[r]);
    }

    block = _mm_aesdeclast_si128(block, dk[rounds]);

    _mm_storeu_si128((__m128i *)ptr, block);
}

JNIEXPORT void JNICALL Java_aes_davidr_engine_AESWC_encryptBlock(
    JNIEnv *env,
    jclass cls,
    jbyteArray inArr,
    jbyteArray keyArr,
    jint rounds,
    jint offset
) {
    jbyte *data = (*env)->GetByteArrayElements(env, inArr, NULL);
    jbyte *ptr = data + offset;
    jbyte *key  = (*env)->GetByteArrayElements(env, keyArr, NULL);

    encrypt_one((uint8_t *)ptr, (const uint8_t *)key, rounds);

    (*env)->ReleaseByteArrayElements(env, inArr, data, 0);
    (*env)->ReleaseByteArrayElements(env, keyArr, key, JNI_ABORT);
}

JNIEXPORT void JNICALL Java_aes_davidr_engine_AESWC_decryptBlock(
    JNIEnv *env,
    jclass cls,
    jbyteArray inArr,
    jbyteArray keyArr,
    jint rounds,
    jint offset
) {
    jbyte *data = (*env)->GetByteArrayElements(env, inArr, NULL);
    jbyte *ptr = data + offset;
    jbyte *key  = (*env)->GetByteArrayElements(env, keyArr, NULL);

    __m128i dk[15];
    make_decrypt_keys((const uint8_t *)key, dk, rounds);

    decrypt_one((uint8_t *)ptr, dk, rounds);

    (*env)->ReleaseByteArrayElements(env, inArr, data, 0);
    (*env)->ReleaseByteArrayElements(env, keyArr, key, JNI_ABORT);
}

JNIEXPORT void JNICALL Java_aes_davidr_engine_AESWC_encryptBlocks(
    JNIEnv *env,
    jclass cls,
    jbyteArray inArr,
    jbyteArray keyArr,
    jint rounds,
    jint offset,
    jint len
) {
    jbyte *data = (*env)->GetByteArrayElements(env, inArr, NULL);
    jbyte *key = (*env)->GetByteArrayElements(env, keyArr, NULL);

    for (jint off = offset; off < offset + len; off += 16) {
        encrypt_one((uint8_t *)(data + off), (const uint8_t *)key, rounds);
    }

    (*env)->ReleaseByteArrayElements(env, inArr, data, 0);
    (*env)->ReleaseByteArrayElements(env, keyArr, key, JNI_ABORT);
}

JNIEXPORT void JNICALL Java_aes_davidr_engine_AESWC_decryptBlocks(
    JNIEnv *env,
    jclass cls,
    jbyteArray inArr,
    jbyteArray keyArr,
    jint rounds,
    jint offset,
    jint len
) {
    jbyte *data = (*env)->GetByteArrayElements(env, inArr, NULL);
    jbyte *key = (*env)->GetByteArrayElements(env, keyArr, NULL);

    __m128i dk[15];
    make_decrypt_keys((const uint8_t *)key, dk, rounds);

    for (jint off = offset; off < offset + len; off += 16) {
        decrypt_one((uint8_t *)(data + off), dk, rounds);
    }

    (*env)->ReleaseByteArrayElements(env, inArr, data, 0);
    (*env)->ReleaseByteArrayElements(env, keyArr, key, JNI_ABORT);
}
