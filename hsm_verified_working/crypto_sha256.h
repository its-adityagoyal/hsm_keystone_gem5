#ifndef _CRYPTO_SHA256_H_
#define _CRYPTO_SHA256_H_

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHA256_DIGEST_SIZE 32
#define SHA256_BLOCK_SIZE  64

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buffer[SHA256_BLOCK_SIZE];
} sha256_ctx_t;

void sha256_init(sha256_ctx_t* ctx);
void sha256_update(sha256_ctx_t* ctx, const uint8_t* data, size_t len);
void sha256_final(sha256_ctx_t* ctx, uint8_t digest[SHA256_DIGEST_SIZE]);
void sha256_hash(const uint8_t* data, size_t len, uint8_t digest[SHA256_DIGEST_SIZE]);

/* HMAC-SHA256 */
typedef struct {
    sha256_ctx_t inner;
    sha256_ctx_t outer;
} hmac_sha256_ctx_t;

void hmac_sha256_init(hmac_sha256_ctx_t* ctx, const uint8_t* key, size_t key_len);
void hmac_sha256_update(hmac_sha256_ctx_t* ctx, const uint8_t* data, size_t len);
void hmac_sha256_final(hmac_sha256_ctx_t* ctx, uint8_t mac[SHA256_DIGEST_SIZE]);
void hmac_sha256(const uint8_t* key, size_t key_len,
                 const uint8_t* data, size_t data_len,
                 uint8_t mac[SHA256_DIGEST_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* _CRYPTO_SHA256_H_ */
