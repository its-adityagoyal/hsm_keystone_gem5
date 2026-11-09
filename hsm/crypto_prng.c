#include "crypto_prng.h"
#include "crypto_sha256.h"
#include <string.h>

static uint8_t prng_state[32];
static uint64_t prng_counter = 0;
static int prng_initialized = 0;

static inline uint64_t get_hardware_cycles(void) {
    static uint64_t counter = 0x5A827999ULL;
    counter = counter * 6364136223846793005ULL + 1442695040888963407ULL;
    return counter;
}

void prng_init(const uint8_t* seed, size_t seed_len) {
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    uint64_t cycles = get_hardware_cycles();
    sha256_update(&ctx, (const uint8_t*)&cycles, sizeof(cycles));
    if (seed && seed_len > 0) {
        sha256_update(&ctx, seed, seed_len);
    }
    sha256_final(&ctx, prng_state);
    prng_counter = 1;
    prng_initialized = 1;
}

void prng_get_random_bytes(uint8_t* out, size_t len) {
    if (!prng_initialized) {
        prng_init(NULL, 0);
    }

    size_t generated = 0;
    while (generated < len) {
        uint8_t block[32];
        sha256_ctx_t ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, prng_state, 32);
        sha256_update(&ctx, (const uint8_t*)&prng_counter, sizeof(prng_counter));
        uint64_t cycles = get_hardware_cycles();
        sha256_update(&ctx, (const uint8_t*)&cycles, sizeof(cycles));
        sha256_final(&ctx, block);

        prng_counter++;

        // Update state to ensure forward secrecy
        sha256_hash(block, 32, prng_state);

        size_t to_copy = (len - generated < 32) ? (len - generated) : 32;
        memcpy(out + generated, block, to_copy);
        generated += to_copy;
    }
}
