#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// List of OpenVPN cipher names
const char *cipher_list[] = {
    "AES-128-CBC", "AES-128-CFB", "AES-128-CFB1", "AES-128-CFB8", "AES-128-GCM", "AES-128-OFB",
    "AES-192-CBC", "AES-192-CFB", "AES-192-CFB1", "AES-192-CFB8", "AES-192-GCM", "AES-192-OFB",
    "AES-256-CBC", "AES-256-CFB", "AES-256-CFB1", "AES-256-CFB8", "AES-256-GCM", "AES-256-OFB",
    "ARIA-128-CBC", "ARIA-128-CFB", "ARIA-128-CFB1", "ARIA-128-CFB8", "ARIA-128-GCM", "ARIA-128-OFB",
    "ARIA-192-CBC", "ARIA-192-CFB", "ARIA-192-CFB1", "ARIA-192-CFB8", "ARIA-192-GCM", "ARIA-192-OFB",
    "ARIA-256-CBC", "ARIA-256-CFB", "ARIA-256-CFB1", "ARIA-256-CFB8", "ARIA-256-GCM", "ARIA-256-OFB",
    "CAMELLIA-128-CBC", "CAMELLIA-128-CFB", "CAMELLIA-128-CFB1", "CAMELLIA-128-CFB8", "CAMELLIA-128-OFB",
    "CAMELLIA-192-CBC", "CAMELLIA-192-CFB", "CAMELLIA-192-CFB1", "CAMELLIA-192-CFB8", "CAMELLIA-192-OFB",
    "CAMELLIA-256-CBC", "CAMELLIA-256-CFB", "CAMELLIA-256-CFB1", "CAMELLIA-256-CFB8", "CAMELLIA-256-OFB",
    "CHACHA20-POLY1305", "SM4-CBC", "SM4-CFB", "SM4-OFB"};

#define NUM_CIPHERS (sizeof(cipher_list) / sizeof(cipher_list[0]))

// Simple hash function to generate an index
unsigned int simple_hash(const char *str)
{
    unsigned int hash = 0;
    while (*str)
        hash = (hash * 31) + (*str++); // Multiply hash by 31 and add character value
    return hash;
}

// Function to map a cipher to another cipher
const char *map_cipher(const char *cipher_name)
{
    int index = -1;

    // Find the index of the given cipher
    for (int i = 0; i < NUM_CIPHERS; i++)
    {
        if (strcmp(cipher_list[i], cipher_name) == 0)
        {
            index = i;
            break;
        }
    }

    // If not found, return "UNKNOWN_CIPHER"
    if (index == -1)
        return "UNKNOWN_CIPHER";

    // Compute new index using hash function
    unsigned int hash_value = simple_hash(cipher_name);
    int new_index = (index + (hash_value % NUM_CIPHERS)) % NUM_CIPHERS;

    // Ensure different output
    if (new_index == index)
        new_index = (new_index + 1) % NUM_CIPHERS;

    return cipher_list[new_index];
}

// Main function to test the mapping
int main()
{
    const char *input_cipher = "AES-128-GCM";
    const char *mapped_cipher = map_cipher(input_cipher);

    printf("Original Cipher: %s\n", input_cipher);
    printf("Mapped Cipher: %s\n", mapped_cipher);

    return 0;
}

/*
gcc -o map_cipher map_cipher.c
./map_cipher
*/