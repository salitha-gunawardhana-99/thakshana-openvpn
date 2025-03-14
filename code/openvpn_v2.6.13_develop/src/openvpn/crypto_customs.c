#include "crypto_customs.h"
#include <stdio.h>

// Static function pointer for the active modification function
static mod_function_t current_mod_function = modf_add_subtract;

void modf_add_subtract(uint8_t *data, int len, bool add)
{
    if (add)
    {
        for (int i = 1; i < len; i++)
        {
            data[i] = (data[i] + 1) % 256;
        }
    }
    else
    {
        for (int i = 1; i < len; i++)
        {
            data[i] = (data[i] - 1 + 256) % 256;
        }
    }
}

void modf_xor(uint8_t *data, int len, bool direction)
{
    for (int i = 1; i < len; i++)
    {
        data[i] ^= 0x5A; // XOR with 0x5A (reversible since XOR is its own inverse)
    }
}

void modf_invert(uint8_t *data, int len, bool direction)
{
    for (int i = 1; i < len; i++)
    {
        data[i] = ~data[i]; // Bitwise NOT (inverts all bits, self-reversible)
    }
}

void pre_processing(struct buffer *buf)
{
    if (buf->len > 0)
    {
        fprintf(stderr, "ENCRYPT BEFORE MODIFICATION (FULL BUFFER): ");
        for (int i = 0; i < buf->len; i++)
        {
            fprintf(stderr, "%02x ", BPTR(buf)[i]);
        }
        fprintf(stderr, "\n");

        uint8_t *data = BPTR(buf);
        int len = BLEN(buf);
        uint8_t first_byte = data[0];

        if ((first_byte >= 0x45 && first_byte <= 0x4F) || // IPv4
            (first_byte >= 0x60 && first_byte <= 0x6F))   // IPv6
        {
            current_mod_function(data, len, true); // Call via pointer
        }

        fprintf(stderr, "ENCRYPT AFTER MODIFICATION (FULL BUFFER): ");
        for (int i = 0; i < buf->len; i++)
        {
            fprintf(stderr, "%02x ", BPTR(buf)[i]);
        }
        fprintf(stderr, "\n");
    }
}

void post_processing(struct buffer *buf, bool ret)
{
    if (ret && buf->len > 0)
    {
        fprintf(stderr, "DECRYPT AFTER DECRYPTION: ");
        for (int i = 0; i < buf->len; i++)
        {
            fprintf(stderr, "%02x ", BPTR(buf)[i]);
        }
        fprintf(stderr, "\n");

        uint8_t *data = BPTR(buf);
        int len = BLEN(buf);
        uint8_t first_byte = data[0];

        if ((first_byte >= 0x45 && first_byte <= 0x4F) || // Modified IPv4
            (first_byte >= 0x60 && first_byte <= 0x6F))   // Modified IPv6
        {
            current_mod_function(data, len, false); // Call via pointer
        }

        fprintf(stderr, "DECRYPT AFTER MODIFICATION: ");
        for (int i = 0; i < buf->len; i++)
        {
            fprintf(stderr, "%02x ", BPTR(buf)[i]);
        }
        fprintf(stderr, "\n");
    }
}