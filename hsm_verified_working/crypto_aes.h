#ifndef _CRYPTO_AES_H_
#define _CRYPTO_AES_H_

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AES_BLOCK_SIZE 16

typedef struct {
    uint32_t round_keys[60];
    int rounds;
} aes_ctx_t;

int aes_set_key(aes_ctx_t* ctx, const uint8_t* key, size_t key_len);
void aes_encrypt_block(const aes_ctx_t* ctx, const uint8_t in[AES_BLOCK_SIZE], uint8_t out[AES_BLOCK_SIZE]);
void aes_decrypt_block(const aes_ctx_t* ctx, const uint8_t in[AES_BLOCK_SIZE], uint8_t out[AES_BLOCK_SIZE]);

/* AES CBC with PKCS#7 Padding */
int aes_cbc_encrypt(const aes_ctx_t* ctx, const uint8_t iv[AES_BLOCK_SIZE],
                    const uint8_t* in, size_t in_len,
                    uint8_t* out, size_t* out_len);

int aes_cbc_decrypt(const aes_ctx_t* ctx, const uint8_t iv[AES_BLOCK_SIZE],
                    const uint8_t* in, size_t in_len,
                    uint8_t* out, size_t* out_len);

#ifdef __cplusplus
}
#endif

#endif /* _CRYPTO_AES_H_ */
