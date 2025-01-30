// xor_cipher.c
#include <string.h>
#include "xor_cipher.h"

int xor_cipher_init(xor_cipher_ctx *ctx, const uint8_t *key, size_t key_length)
{
    if (!ctx || !key || key_length == 0 || key_length > 256)
    {
        return -1;
    }

    // Store the key
    memcpy(ctx->key, key, key_length);
    ctx->key_length = key_length;

    return 0;
}

int xor_cipher_encrypt(xor_cipher_ctx *ctx, const uint8_t *plaintext,
                       uint8_t *ciphertext, size_t length)
{
    if (!ctx || !plaintext || !ciphertext || length == 0)
    {
        return -1;
    }

    // Apply XOR operation with key in a rotating fashion
    for (size_t i = 0; i < length; i++)
    {
        ciphertext[i] = plaintext[i] ^ ctx->key[i % ctx->key_length];
    }

    return 0;
}

int xor_cipher_decrypt(xor_cipher_ctx *ctx, const uint8_t *ciphertext,
                       uint8_t *plaintext, size_t length)
{
    // XOR is symmetric, so encryption and decryption are the same operation
    return xor_cipher_encrypt(ctx, ciphertext, plaintext, length);
}