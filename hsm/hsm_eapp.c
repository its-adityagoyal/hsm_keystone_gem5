#include "app/eapp_utils.h"
#include "app/string.h"
#include "app/syscall.h"
#include "hsm_protocol.h"
#include "key_store.h"
#include "crypto_aes.h"
#include "crypto_sha256.h"
#include "crypto_prng.h"

static void process_hsm_command(const hsm_req_t* req, hsm_resp_t* resp) {
    memset(resp, 0, sizeof(hsm_resp_t));

    switch (req->cmd_id) {
        case HSM_CMD_GET_STATUS: {
            resp->status = HSM_STATUS_OK;
            break;
        }

        case HSM_CMD_GEN_KEY: {
            uint32_t handle = 0;
            size_t key_len = (req->key_type == HSM_KEY_TYPE_AES128) ? 16 : 32;
            int ret = key_store_generate_key(req->key_type, req->usage_flags, key_len, &handle);
            resp->status = (ret == HSM_STATUS_OK) ? HSM_STATUS_OK : ret;
            resp->key_handle = handle;
            resp->key_type = req->key_type;
            resp->usage_flags = req->usage_flags;
            break;
        }

        case HSM_CMD_GEN_KEYPAIR: {
            uint32_t handle = 0;
            size_t pub_len = 32;
            int ret = key_store_generate_keypair(req->key_type, req->usage_flags,
                                                 &handle, resp->out_data, &pub_len);
            resp->status = (ret == HSM_STATUS_OK) ? HSM_STATUS_OK : ret;
            resp->key_handle = handle;
            resp->key_type = req->key_type;
            resp->usage_flags = req->usage_flags;
            resp->out_data_len = (uint32_t)pub_len;
            break;
        }

        case HSM_CMD_DESTROY_KEY: {
            int ret = key_store_destroy_key(req->key_handle);
            resp->status = (ret == HSM_STATUS_OK) ? HSM_STATUS_OK : ret;
            resp->key_handle = req->key_handle;
            break;
        }

        case HSM_CMD_GET_KEY_INFO: {
            uint32_t ktype = 0, uflags = 0;
            size_t klen = 0;
            int ret = key_store_get_info(req->key_handle, &ktype, &uflags, &klen);
            resp->status = (ret == HSM_STATUS_OK) ? HSM_STATUS_OK : ret;
            resp->key_handle = req->key_handle;
            resp->key_type = ktype;
            resp->usage_flags = uflags;
            resp->out_data_len = (uint32_t)klen;
            break;
        }

        case HSM_CMD_ENCRYPT: {
            key_slot_t* slot = key_store_lookup(req->key_handle);
            if (!slot) {
                resp->status = HSM_STATUS_ERR_INVALID_HANDLE;
                break;
            }
            if (!(slot->usage_flags & HSM_USAGE_ENCRYPT)) {
                resp->status = HSM_STATUS_ERR_PERM_DENIED;
                break;
            }
            if (slot->key_type != HSM_KEY_TYPE_AES128 && slot->key_type != HSM_KEY_TYPE_AES256) {
                resp->status = HSM_STATUS_ERR_INVALID_PARAM;
                break;
            }

            aes_ctx_t aes_ctx;
            if (aes_set_key(&aes_ctx, slot->key_material, slot->key_len) != 0) {
                resp->status = HSM_STATUS_ERR_CRYPTO_FAIL;
                break;
            }

            size_t out_len = sizeof(resp->out_data);
            if (aes_cbc_encrypt(&aes_ctx, req->iv, req->in_data, req->in_data_len,
                                resp->out_data, &out_len) != 0) {
                resp->status = HSM_STATUS_ERR_CRYPTO_FAIL;
                break;
            }

            resp->status = HSM_STATUS_OK;
            resp->key_handle = req->key_handle;
            resp->out_data_len = (uint32_t)out_len;
            break;
        }

        case HSM_CMD_DECRYPT: {
            key_slot_t* slot = key_store_lookup(req->key_handle);
            if (!slot) {
                resp->status = HSM_STATUS_ERR_INVALID_HANDLE;
                break;
            }
            if (!(slot->usage_flags & HSM_USAGE_DECRYPT)) {
                resp->status = HSM_STATUS_ERR_PERM_DENIED;
                break;
            }
            if (slot->key_type != HSM_KEY_TYPE_AES128 && slot->key_type != HSM_KEY_TYPE_AES256) {
                resp->status = HSM_STATUS_ERR_INVALID_PARAM;
                break;
            }

            aes_ctx_t aes_ctx;
            if (aes_set_key(&aes_ctx, slot->key_material, slot->key_len) != 0) {
                resp->status = HSM_STATUS_ERR_CRYPTO_FAIL;
                break;
            }

            size_t out_len = sizeof(resp->out_data);
            if (aes_cbc_decrypt(&aes_ctx, req->iv, req->in_data, req->in_data_len,
                                resp->out_data, &out_len) != 0) {
                resp->status = HSM_STATUS_ERR_CRYPTO_FAIL;
                break;
            }

            resp->status = HSM_STATUS_OK;
            resp->key_handle = req->key_handle;
            resp->out_data_len = (uint32_t)out_len;
            break;
        }

        case HSM_CMD_DIGEST: {
            sha256_hash(req->in_data, req->in_data_len, resp->out_data);
            resp->status = HSM_STATUS_OK;
            resp->out_data_len = 32;
            break;
        }

        case HSM_CMD_SIGN: {
            key_slot_t* slot = key_store_lookup(req->key_handle);
            if (!slot) {
                resp->status = HSM_STATUS_ERR_INVALID_HANDLE;
                break;
            }
            if (!(slot->usage_flags & HSM_USAGE_SIGN)) {
                resp->status = HSM_STATUS_ERR_PERM_DENIED;
                break;
            }

            if (slot->key_type == HSM_KEY_TYPE_HMAC_SHA256) {
                hmac_sha256(slot->key_material, slot->key_len,
                            req->in_data, req->in_data_len,
                            resp->out_data);
                resp->status = HSM_STATUS_OK;
                resp->out_data_len = 32;
            } else {
                resp->status = HSM_STATUS_ERR_INVALID_PARAM;
            }
            resp->key_handle = req->key_handle;
            break;
        }

        case HSM_CMD_VERIFY: {
            key_slot_t* slot = key_store_lookup(req->key_handle);
            if (!slot) {
                resp->status = HSM_STATUS_ERR_INVALID_HANDLE;
                break;
            }
            if (!(slot->usage_flags & HSM_USAGE_VERIFY)) {
                resp->status = HSM_STATUS_ERR_PERM_DENIED;
                break;
            }

            if (slot->key_type == HSM_KEY_TYPE_HMAC_SHA256) {
                if (req->in_data_len < 32) {
                    resp->status = HSM_STATUS_ERR_INVALID_PARAM;
                    break;
                }
                const uint8_t* provided_mac = req->in_data;
                const uint8_t* msg = req->in_data + 32;
                size_t msg_len = req->in_data_len - 32;
                uint8_t expected_mac[32];
                hmac_sha256(slot->key_material, slot->key_len,
                            msg, msg_len, expected_mac);
                int diff = 0;
                for (int i = 0; i < 32; i++) {
                    diff |= (expected_mac[i] ^ provided_mac[i]);
                }
                resp->status = (diff == 0) ? HSM_STATUS_OK : HSM_STATUS_ERR_CRYPTO_FAIL;
            } else {
                resp->status = HSM_STATUS_ERR_INVALID_PARAM;
            }
            resp->key_handle = req->key_handle;
            break;
        }

        default:
            resp->status = HSM_STATUS_ERR_INVALID_CMD;
            break;
    }
}

int main(void) {
    key_store_init();
    prng_init(NULL, 0);

    hsm_resp_t resp;
    memset(&resp, 0, sizeof(hsm_resp_t));
    resp.status = HSM_STATUS_READY;

    hsm_req_t req;

    /* Secure Command Loop: Enclave runs inside Keystone isolation boundary */
    while (1) {
        memset(&req, 0, sizeof(hsm_req_t));
        /* Send previous response and wait for next request via edge call */
        ocall(OCALL_HSM_DISPATCH, &resp, sizeof(hsm_resp_t), &req, sizeof(hsm_req_t));

        if (req.cmd_id == HSM_CMD_SHUTDOWN) {
            // Clean shutdown: zeroize all keys in enclave memory
            key_store_init();
            break;
        }

        process_hsm_command(&req, &resp);
    }

    EAPP_RETURN(0);
}
