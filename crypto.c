/*
 * crypto.c - AES-256-CBC, PBKDF2, HMAC-SHA256 using Windows BCrypt API
 * Windows BCrypt is a SYSTEM library (like user32, kernel32), not external.
 */
#include "crypto.h"
#include <stdlib.h>
#include <string.h>

void secure_wipe(void *p, size_t n) {
    SecureZeroMemory(p, n);
}

int secure_rand(uint8_t *buf, size_t len) {
    return BCryptGenRandom(NULL, buf, (ULONG)len,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 ? 1 : 0;
}

/* ---------- AES-256-CBC Encrypt (PKCS7 padding) ---------- */
uint8_t *aes_cbc_encrypt(const uint8_t *plain, size_t len,
    const uint8_t key[32], const uint8_t iv[16], size_t *outLen)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    uint8_t *result = NULL;
    ULONG cbResult = 0;
    uint8_t ivCopy[16];

    *outLen = 0;
    memcpy(ivCopy, iv, 16); /* BCrypt modifies IV in-place */

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0)
        return NULL;
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

    if (BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
            (PUCHAR)key, 32, 0) != 0)
        goto cleanup;

    /* Query output size */
    if (BCryptEncrypt(hKey, (PUCHAR)plain, (ULONG)len, NULL,
            ivCopy, 16, NULL, 0, &cbResult,
            BCRYPT_BLOCK_PADDING) != 0)
        goto cleanup;

    result = (uint8_t *)malloc(cbResult);
    if (!result) goto cleanup;
    memcpy(ivCopy, iv, 16);

    if (BCryptEncrypt(hKey, (PUCHAR)plain, (ULONG)len, NULL,
            ivCopy, 16, result, cbResult, &cbResult,
            BCRYPT_BLOCK_PADDING) != 0) {
        free(result);
        result = NULL;
        goto cleanup;
    }
    *outLen = cbResult;

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}

/* ---------- AES-256-CBC Decrypt (PKCS7 padding) ---------- */
uint8_t *aes_cbc_decrypt(const uint8_t *cipher, size_t len,
    const uint8_t key[32], const uint8_t iv[16], size_t *outLen)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    uint8_t *result = NULL;
    ULONG cbResult = 0;
    uint8_t ivCopy[16];

    *outLen = 0;
    if (len == 0 || len % 16 != 0) return NULL;
    memcpy(ivCopy, iv, 16);

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0)
        return NULL;
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

    if (BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
            (PUCHAR)key, 32, 0) != 0)
        goto cleanup;

    /* Query output size */
    if (BCryptDecrypt(hKey, (PUCHAR)cipher, (ULONG)len, NULL,
            ivCopy, 16, NULL, 0, &cbResult,
            BCRYPT_BLOCK_PADDING) != 0)
        goto cleanup;

    result = (uint8_t *)malloc(cbResult);
    if (!result) goto cleanup;
    memcpy(ivCopy, iv, 16);

    if (BCryptDecrypt(hKey, (PUCHAR)cipher, (ULONG)len, NULL,
            ivCopy, 16, result, cbResult, &cbResult,
            BCRYPT_BLOCK_PADDING) != 0) {
        free(result);
        result = NULL;
        goto cleanup;
    }
    *outLen = cbResult;

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}

/* ---------- PBKDF2-HMAC-SHA256 ---------- */
int pbkdf2(const uint8_t *pw, size_t pwlen, const uint8_t *salt, size_t slen,
    uint32_t iter, uint8_t *dk, size_t dklen)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    int ok = 0;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM,
            NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
        return 0;

    if (BCryptDeriveKeyPBKDF2(hAlg, (PUCHAR)pw, (ULONG)pwlen,
            (PUCHAR)salt, (ULONG)slen, iter,
            dk, (ULONG)dklen, 0) == 0)
        ok = 1;

    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

/* ---------- HMAC-SHA256 ---------- */
int hmac_sha256(const uint8_t *key, size_t klen,
    const uint8_t *msg, size_t mlen, uint8_t out[32])
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    int ok = 0;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM,
            NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
        return 0;

    if (BCryptCreateHash(hAlg, &hHash, NULL, 0,
            (PUCHAR)key, (ULONG)klen, 0) != 0)
        goto cleanup;

    if (BCryptHashData(hHash, (PUCHAR)msg, (ULONG)mlen, 0) != 0)
        goto cleanup;

    if (BCryptFinishHash(hHash, out, 32, 0) == 0)
        ok = 1;

cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}
