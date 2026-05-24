#ifndef CRYPTO_H
#define CRYPTO_H
#include <windows.h>
#include <bcrypt.h>
#include <stdint.h>
#pragma comment(lib, "bcrypt.lib")

#define AES_KEY_SIZE   32
#define AES_BLOCK_SIZE 16
#define SHA256_SIZE    32
#define PBKDF2_ITER    100000
#define SALT_SIZE      16

/* AES-256-CBC encrypt (PKCS7). Caller frees returned buffer. */
uint8_t *aes_cbc_encrypt(const uint8_t *plain, size_t len,
    const uint8_t key[32], const uint8_t iv[16], size_t *outLen);

/* AES-256-CBC decrypt (PKCS7). Caller frees returned buffer. */
uint8_t *aes_cbc_decrypt(const uint8_t *cipher, size_t len,
    const uint8_t key[32], const uint8_t iv[16], size_t *outLen);

/* PBKDF2-HMAC-SHA256 key derivation */
int pbkdf2(const uint8_t *pw, size_t pwlen, const uint8_t *salt, size_t slen,
    uint32_t iter, uint8_t *dk, size_t dklen);

/* HMAC-SHA256 */
int hmac_sha256(const uint8_t *key, size_t klen,
    const uint8_t *msg, size_t mlen, uint8_t out[32]);

/* Fill buffer with cryptographic random bytes */
int secure_rand(uint8_t *buf, size_t len);

/* Securely wipe memory */
void secure_wipe(void *p, size_t n);

#endif
