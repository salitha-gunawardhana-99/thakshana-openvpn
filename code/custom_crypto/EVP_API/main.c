#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

void handle_errors()
{
    // Handle OpenSSL errors
}

int main()
{
    unsigned char key[32]; // 256-bit key
    unsigned char iv[16];  // 128-bit IV
    unsigned char plaintext[] = "Hello, OpenSSL EVP!";
    unsigned char ciphertext[128];
    unsigned char decryptedtext[128];
    int ciphertext_len, decryptedtext_len;

    // Generate random key and IV
    // Generate random key and IV
    if (!RAND_bytes(key, sizeof(key)))
        handle_errors();
    if (!RAND_bytes(iv, sizeof(iv)))
        handle_errors();

    // Encrypt
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        handle_errors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handle_errors();
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, strlen((char *)plaintext)))
        handle_errors();
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &ciphertext_len))
        handle_errors();

    EVP_CIPHER_CTX_free(ctx);

    // Decrypt
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        handle_errors();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handle_errors();
    if (1 != EVP_DecryptUpdate(ctx, decryptedtext, &decryptedtext_len, ciphertext, ciphertext_len))
        handle_errors();
    if (1 != EVP_DecryptFinal_ex(ctx, decryptedtext + decryptedtext_len, &decryptedtext_len))
        handle_errors();

    EVP_CIPHER_CTX_free(ctx);

    // Print results
    printf("Decrypted text: %s\n", decryptedtext);

    return 0;
}