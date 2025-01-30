#include "xor_cipher.h"

void xor_encrypt(const unsigned char *input, unsigned char *output, size_t length, const unsigned char *key, size_t key_length)
{
    for (size_t i = 0; i < length; i++)
    {
        output[i] = input[i] ^ key[i % key_length];
    }
}

void xor_decrypt(const unsigned char *input, unsigned char *output, size_t length, const unsigned char *key, size_t key_length)
{
    // XOR decryption is the same as encryption
    xor_encrypt(input, output, length, key, key_length);
}