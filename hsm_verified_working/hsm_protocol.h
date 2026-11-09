#ifndef _HSM_PROTOCOL_H_
#define _HSM_PROTOCOL_H_

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Ocall call ID for HSM IPC dispatch */
#define OCALL_HSM_DISPATCH 5

/* HSM Commands */
enum hsm_cmd_id {
    HSM_CMD_NONE            = 0,
    HSM_CMD_GET_STATUS      = 1,
    HSM_CMD_GEN_KEY         = 2,
    HSM_CMD_GEN_KEYPAIR     = 3,
    HSM_CMD_DESTROY_KEY     = 4,
    HSM_CMD_ENCRYPT         = 5,
    HSM_CMD_DECRYPT         = 6,
    HSM_CMD_DIGEST          = 7,
    HSM_CMD_SIGN            = 8,
    HSM_CMD_VERIFY          = 9,
    HSM_CMD_GET_KEY_INFO    = 10,
    HSM_CMD_SHUTDOWN        = 11
};

/* HSM Key Types */
enum hsm_key_type {
    HSM_KEY_TYPE_NONE        = 0,
    HSM_KEY_TYPE_AES128      = 1,
    HSM_KEY_TYPE_AES256      = 2,
    HSM_KEY_TYPE_HMAC_SHA256 = 3,
    HSM_KEY_TYPE_ED25519     = 4
};

/* HSM Key Usage Flags */
#define HSM_USAGE_ENCRYPT (1 << 0)
#define HSM_USAGE_DECRYPT (1 << 1)
#define HSM_USAGE_SIGN    (1 << 2)
#define HSM_USAGE_VERIFY  (1 << 3)

/* HSM Return Status Codes */
enum hsm_status {
    HSM_STATUS_OK                 = 0,
    HSM_STATUS_READY              = 1,
    HSM_STATUS_ERR_GENERAL        = 2,
    HSM_STATUS_ERR_INVALID_CMD    = 3,
    HSM_STATUS_ERR_INVALID_HANDLE = 4,
    HSM_STATUS_ERR_PERM_DENIED    = 5,
    HSM_STATUS_ERR_NO_SLOTS       = 6,
    HSM_STATUS_ERR_INVALID_PARAM  = 7,
    HSM_STATUS_ERR_CRYPTO_FAIL    = 8,
    HSM_STATUS_ERR_BUFFER_TOO_SM  = 9
};

/* Maximum payload size per request/response in bytes */
#define HSM_MAX_PAYLOAD_SIZE 1024

/* HSM Request Packet (Host -> Enclave) */
typedef struct {
    uint32_t cmd_id;
    uint32_t key_handle;       /* Handle for crypto ops or destruction */
    uint32_t key_type;         /* For key generation */
    uint32_t usage_flags;      /* Key permissions */
    uint32_t in_data_len;      /* Length of in_data */
    uint8_t  iv[16];           /* IV for AES CBC */
    uint8_t  in_data[HSM_MAX_PAYLOAD_SIZE];
} hsm_req_t;

/* HSM Response Packet (Enclave -> Host) */
typedef struct {
    uint32_t status;           /* enum hsm_status */
    uint32_t key_handle;       /* Generated handle, if applicable */
    uint32_t key_type;
    uint32_t usage_flags;
    uint32_t out_data_len;     /* Length of out_data */
    uint8_t  out_data[HSM_MAX_PAYLOAD_SIZE];
} hsm_resp_t;

#ifdef __cplusplus
}
#endif

#endif /* _HSM_PROTOCOL_H_ */
