#ifndef _KEY_STORE_H_
#define _KEY_STORE_H_

#include <stdint.h>
#include <stddef.h>
#include "hsm_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_KEY_SLOTS 64
#define HANDLE_BASE   0x1000

typedef struct {
    uint32_t handle;
    uint32_t key_type;
    uint32_t usage_flags;
    size_t   key_len;
    uint8_t  key_material[64];
    uint8_t  public_key[32];   /* For asymmetric keypairs */
    int      in_use;
} key_slot_t;

void key_store_init(void);

int key_store_generate_key(uint32_t key_type, uint32_t usage_flags, size_t key_len,
                           uint32_t* out_handle);

int key_store_generate_keypair(uint32_t key_type, uint32_t usage_flags,
                               uint32_t* out_handle,
                               uint8_t* out_public_key, size_t* out_public_key_len);

key_slot_t* key_store_lookup(uint32_t handle);

int key_store_destroy_key(uint32_t handle);

int key_store_get_info(uint32_t handle, uint32_t* out_key_type,
                       uint32_t* out_usage_flags, size_t* out_key_len);

#ifdef __cplusplus
}
#endif

#endif /* _KEY_STORE_H_ */
