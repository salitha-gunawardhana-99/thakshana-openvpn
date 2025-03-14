#ifndef CRYPTO_CUSTOMS_H
#define CRYPTO_CUSTOMS_H

#include <sys/time.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "buffer.h"

// Function pointer type for modification functions
typedef void (*mod_function_t)(uint8_t *data, int len, bool direction);

// Function declarations
void modf_add_subtract(uint8_t *data, int len, bool direction);
void modf_xor(uint8_t *data, int len, bool direction);
void modf_invert(uint8_t *data, int len, bool direction);

void pre_processing(struct buffer *buf);
void post_processing(struct buffer *buf, bool ret);

#endif /* CRYPTO_CUSTOMS_H */