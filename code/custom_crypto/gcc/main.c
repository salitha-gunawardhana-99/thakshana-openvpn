#include <stdio.h>
#include <string.h>
#include "xor_cipher.h"

int main()
{
    // Example key and data
    const unsigned char key[] = "secretkey";
    const unsigned char plaintext[] = "Hello, OpenVPN!";
    size_t plaintext_length = strlen((const char *)plaintext);
    size_t key_length = strlen((const char *)key);

    // Buffers for encrypted and decrypted data
    unsigned char encrypted[plaintext_length + 1];
    unsigned char decrypted[plaintext_length + 1];

    // Encrypt the plaintext
    xor_encrypt(plaintext, encrypted, plaintext_length, key, key_length);
    encrypted[plaintext_length] = '\0'; // Null-terminate the string

    // Decrypt the ciphertext
    xor_decrypt(encrypted, decrypted, plaintext_length, key, key_length);
    decrypted[plaintext_length] = '\0'; // Null-terminate the string

    // Print results
    printf("Original: %s\n", plaintext);
    printf("Encrypted: ");
    for (size_t i = 0; i < plaintext_length; i++)
    {
        printf("%02x ", encrypted[i]);
    }
    printf("\n");
    printf("Decrypted: %s\n", decrypted);

    return 0;
}