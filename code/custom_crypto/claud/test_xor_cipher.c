// test_xor_cipher.c
#include <stdio.h>
#include <string.h>
#include "xor_cipher.h"

void print_hex(const uint8_t *data, size_t length)
{
    for (size_t i = 0; i < length; i++)
    {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

int main()
{
    // Test vectors
    uint8_t key[] = "SecretKey123";
    uint8_t plaintext[] = "Hello, OpenVPN!";
    size_t text_length = strlen((char *)plaintext);
    uint8_t ciphertext[256];
    uint8_t decrypted[256];

    // Initialize cipher context
    xor_cipher_ctx ctx;
    if (xor_cipher_init(&ctx, key, strlen((char *)key)) != 0)
    {
        printf("Failed to initialize cipher context\n");
        return -1;
    }

    // Encrypt
    printf("Original text: %s\n", plaintext);
    printf("Original hex: ");
    print_hex(plaintext, text_length);

    if (xor_cipher_encrypt(&ctx, plaintext, ciphertext, text_length) != 0)
    {
        printf("Encryption failed\n");
        return -1;
    }

    printf("Encrypted hex: ");
    print_hex(ciphertext, text_length);

    // Decrypt
    if (xor_cipher_decrypt(&ctx, ciphertext, decrypted, text_length) != 0)
    {
        printf("Decryption failed\n");
        return -1;
    }

    decrypted[text_length] = '\0'; // Null terminate for string printing
    printf("Decrypted text: %s\n", decrypted);
    printf("Decrypted hex: ");
    print_hex(decrypted, text_length);

    // Verify
    if (memcmp(plaintext, decrypted, text_length) == 0)
    {
        printf("Test passed: Encryption/decryption successful!\n");
    }
    else
    {
        printf("Test failed: Decrypted text doesn't match original!\n");
    }

    return 0;
}