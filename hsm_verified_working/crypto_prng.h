#ifndef _CRYPTO_PRNG_H_
#define _CRYPTO_PRNG_H_

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void prng_init(const uint8_t* seed, size_t seed_len);
void prng_get_random_bytes(uint8_t* out, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* _CRYPTO_PRNG_H_ */
