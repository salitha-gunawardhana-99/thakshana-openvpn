#ifndef XOR_CIPHER_H
#define XOR_CIPHER_H

#include <stddef.h>

// Function to encrypt data using XOR cipher
void xor_encrypt(const unsigned char *input, unsigned char *output, size_t length, const unsigned char *key, size_t key_length);

// Function to decrypt data using XOR cipher
void xor_decrypt(const unsigned char *input, unsigned char *output, size_t length, const unsigned char *key, size_t key_length);

#endif // XOR_CIPHER_H