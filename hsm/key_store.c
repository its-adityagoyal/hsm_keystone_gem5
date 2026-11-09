#include "key_store.h"
#include "crypto_prng.h"
#include <string.h>

static key_slot_t key_table[MAX_KEY_SLOTS];
static uint32_t next_handle_seq = 1;

void key_store_init(void) {
    memset(key_table, 0, sizeof(key_table));
    next_handle_seq = 1;
}

static uint32_t alloc_new_handle(void) {
    return HANDLE_BASE + (next_handle_seq++);
}

static int find_free_slot(void) {
    for (int i = 0; i < MAX_KEY_SLOTS; i++) {
        if (!key_table[i].in_use) {
            return i;
        }
    }
    return -1;
}

int key_store_generate_key(uint32_t key_type, uint32_t usage_flags, size_t key_len,
                           uint32_t* out_handle) {
    int slot_idx = find_free_slot();
    if (slot_idx < 0) {
        return HSM_STATUS_ERR_NO_SLOTS;
    }

    if (key_type == HSM_KEY_TYPE_AES128) {
        key_len = 16;
    } else if (key_type == HSM_KEY_TYPE_AES256) {
        key_len = 32;
    } else if (key_type == HSM_KEY_TYPE_HMAC_SHA256) {
        if (key_len == 0 || key_len > 64) key_len = 32;
    } else {
        return HSM_STATUS_ERR_INVALID_PARAM;
    }

    key_slot_t* slot = &key_table[slot_idx];
    memset(slot, 0, sizeof(key_slot_t));

    prng_get_random_bytes(slot->key_material, key_len);

    slot->handle = alloc_new_handle();
    slot->key_type = key_type;
    slot->usage_flags = usage_flags;
    slot->key_len = key_len;
    slot->in_use = 1;

    *out_handle = slot->handle;
    return HSM_STATUS_OK;
}

int key_store_generate_keypair(uint32_t key_type, uint32_t usage_flags,
                               uint32_t* out_handle,
                               uint8_t* out_public_key, size_t* out_public_key_len) {
    (void)key_type; (void)usage_flags; (void)out_handle;
    (void)out_public_key; (void)out_public_key_len;
    return HSM_STATUS_ERR_INVALID_PARAM;
}

key_slot_t* key_store_lookup(uint32_t handle) {
    if (handle < HANDLE_BASE) return NULL;
    for (int i = 0; i < MAX_KEY_SLOTS; i++) {
        if (key_table[i].in_use && key_table[i].handle == handle) {
            return &key_table[i];
        }
    }
    return NULL;
}

int key_store_destroy_key(uint32_t handle) {
    for (int i = 0; i < MAX_KEY_SLOTS; i++) {
        if (key_table[i].in_use && key_table[i].handle == handle) {
            // Zeroize sensitive key material
            memset(key_table[i].key_material, 0, sizeof(key_table[i].key_material));
            memset(key_table[i].public_key, 0, sizeof(key_table[i].public_key));
            key_table[i].in_use = 0;
            key_table[i].handle = 0;
            return HSM_STATUS_OK;
        }
    }
    return HSM_STATUS_ERR_INVALID_HANDLE;
}

int key_store_get_info(uint32_t handle, uint32_t* out_key_type,
                       uint32_t* out_usage_flags, size_t* out_key_len) {
    key_slot_t* slot = key_store_lookup(handle);
    if (!slot) return HSM_STATUS_ERR_INVALID_HANDLE;

    if (out_key_type) *out_key_type = slot->key_type;
    if (out_usage_flags) *out_usage_flags = slot->usage_flags;
    if (out_key_len) *out_key_len = slot->key_len;
    return HSM_STATUS_OK;
}
