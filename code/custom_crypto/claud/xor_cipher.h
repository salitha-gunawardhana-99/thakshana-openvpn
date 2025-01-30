// xor_cipher.h
#ifndef XOR_CIPHER_H
#define XOR_CIPHER_H

#include <stdint.h>
#include <stddef.h>

// Structure to hold cipher context
typedef struct
{
    uint8_t key[256];
    size_t key_length;
} xor_cipher_ctx;

// Function declarations
int xor_cipher_init(xor_cipher_ctx *ctx, const uint8_t *key, size_t key_length);
int xor_cipher_encrypt(xor_cipher_ctx *ctx, const uint8_t *plaintext,
                       uint8_t *ciphertext, size_t length);
int xor_cipher_decrypt(xor_cipher_ctx *ctx, const uint8_t *ciphertext,
                       uint8_t *plaintext, size_t length);

#endif // XOR_CIPHER_H