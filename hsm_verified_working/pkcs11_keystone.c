#include "pkcs11.h"
#include "hsm_host.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define MAX_SESSIONS 16

typedef struct {
    CK_SESSION_HANDLE handle;
    int               is_active;
    CK_OBJECT_HANDLE  encrypt_key;
    uint8_t           encrypt_iv[16];
    CK_OBJECT_HANDLE  decrypt_key;
    uint8_t           decrypt_iv[16];
    CK_OBJECT_HANDLE  sign_key;
    CK_OBJECT_HANDLE  verify_key;
    CK_MECHANISM_TYPE digest_mech;
    int               digest_active;
} session_state_t;

static session_state_t g_sessions[MAX_SESSIONS];
static int g_initialized = 0;
static CK_SESSION_HANDLE g_next_session_handle = 1;

static session_state_t* get_session(CK_SESSION_HANDLE hSession) {
    if (hSession == 0) return NULL;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (g_sessions[i].is_active && g_sessions[i].handle == hSession) {
            return &g_sessions[i];
        }
    }
    return NULL;
}

CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
    (void)pInitArgs;
    if (g_initialized) {
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }

    memset(g_sessions, 0, sizeof(g_sessions));
    g_next_session_handle = 1;

    /* Initialize HSM Enclave Service */
    const char* eapp_path = getenv("KEYSTONE_HSM_EAPP");
    const char* rt_path = getenv("KEYSTONE_HSM_RUNTIME");
    if (!eapp_path) eapp_path = "hsm-eapp";
    if (!rt_path) rt_path = "eyrie-rt";

    if (hsm_host_init(eapp_path, rt_path) != 0) {
        return CKR_DEVICE_ERROR;
    }

    g_initialized = 1;
    return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved) {
    (void)pReserved;
    if (!g_initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    hsm_host_destroy();
    memset(g_sessions, 0, sizeof(g_sessions));
    g_initialized = 0;
    return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo) {
    if (!pInfo) return CKR_ARGUMENTS_BAD;
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;

    memset(pInfo, 0, sizeof(CK_INFO));
    pInfo->cryptokiVersion.major = 2;
    pInfo->cryptokiVersion.minor = 40;
    memcpy(pInfo->manufacturerID, "IIT Kharagpur BTP Keystone HSM ", 32);
    memcpy(pInfo->libraryDescription, "RISC-V Enclave Hardware Sec Mod ", 32);
    pInfo->libraryVersion.major = 1;
    pInfo->libraryVersion.minor = 0;
    return CKR_OK;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
                    CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession) {
    (void)slotID; (void)flags; (void)pApplication; (void)Notify;
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!phSession) return CKR_ARGUMENTS_BAD;

    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_sessions[i].is_active) {
            g_sessions[i].is_active = 1;
            g_sessions[i].handle = g_next_session_handle++;
            *phSession = g_sessions[i].handle;
            return CKR_OK;
        }
    }
    return CKR_HOST_MEMORY;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    session_state_t* s = get_session(hSession);
    if (!s) return CKR_SESSION_HANDLE_INVALID;

    memset(s, 0, sizeof(session_state_t));
    return CKR_OK;
}

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                    CK_OBJECT_HANDLE_PTR phKey) {
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!get_session(hSession)) return CKR_SESSION_HANDLE_INVALID;
    if (!pMechanism || !phKey) return CKR_ARGUMENTS_BAD;

    hsm_req_t req;
    hsm_resp_t resp;
    memset(&req, 0, sizeof(hsm_req_t));

    req.cmd_id = HSM_CMD_GEN_KEY;
    req.usage_flags = HSM_USAGE_ENCRYPT | HSM_USAGE_DECRYPT | HSM_USAGE_SIGN | HSM_USAGE_VERIFY;

    if (pMechanism->mechanism == CKM_AES_KEY_GEN) {
        req.key_type = HSM_KEY_TYPE_AES256; /* Default */
        for (CK_ULONG i = 0; i < ulCount; i++) {
            if (pTemplate[i].type == CKA_VALUE_LEN) {
                CK_ULONG val_len = *(CK_ULONG_PTR)pTemplate[i].pValue;
                if (val_len == 16) {
                    req.key_type = HSM_KEY_TYPE_AES128;
                } else if (val_len == 32) {
                    req.key_type = HSM_KEY_TYPE_AES256;
                }
            }
        }
    } else if (pMechanism->mechanism == CKM_SHA256_HMAC_KEY_GEN) {
        req.key_type = HSM_KEY_TYPE_HMAC_SHA256;
    } else {
        return CKR_MECHANISM_INVALID;
    }

    if (hsm_host_send_command(&req, &resp) != 0 || resp.status != HSM_STATUS_OK) {
        return CKR_FUNCTION_FAILED;
    }

    *phKey = (CK_OBJECT_HANDLE)resp.key_handle;
    return CKR_OK;
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                        CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
                        CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
                        CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey) {
    (void)pPublicKeyTemplate; (void)ulPublicKeyAttributeCount;
    (void)pPrivateKeyTemplate; (void)ulPrivateKeyAttributeCount;

    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!get_session(hSession)) return CKR_SESSION_HANDLE_INVALID;
    if (!pMechanism || !phPublicKey || !phPrivateKey) return CKR_ARGUMENTS_BAD;

    if (pMechanism->mechanism != CKM_EC_EDWARDS_KEY_PAIR_GEN) {
        return CKR_MECHANISM_INVALID;
    }

    hsm_req_t req;
    hsm_resp_t resp;
    memset(&req, 0, sizeof(hsm_req_t));

    req.cmd_id = HSM_CMD_GEN_KEYPAIR;
    req.key_type = HSM_KEY_TYPE_ED25519;
    req.usage_flags = HSM_USAGE_SIGN | HSM_USAGE_VERIFY;

    if (hsm_host_send_command(&req, &resp) != 0 || resp.status != HSM_STATUS_OK) {
        return CKR_FUNCTION_FAILED;
    }

    *phPrivateKey = (CK_OBJECT_HANDLE)resp.key_handle;
    *phPublicKey  = (CK_OBJECT_HANDLE)resp.key_handle;
    return CKR_OK;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) {
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!get_session(hSession)) return CKR_SESSION_HANDLE_INVALID;
    if (hObject == 0) return CKR_OBJECT_HANDLE_INVALID;

    hsm_req_t req;
    hsm_resp_t resp;
    memset(&req, 0, sizeof(hsm_req_t));

    req.cmd_id = HSM_CMD_DESTROY_KEY;
    req.key_handle = (uint32_t)hObject;

    if (hsm_host_send_command(&req, &resp) != 0 || resp.status != HSM_STATUS_OK) {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    return CKR_OK;
}

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    session_state_t* s = get_session(hSession);
    if (!s) return CKR_SESSION_HANDLE_INVALID;
    if (!pMechanism) return CKR_ARGUMENTS_BAD;
    if (pMechanism->mechanism != CKM_AES_CBC_PAD) return CKR_MECHANISM_INVALID;

    s->encrypt_key = hKey;
    if (pMechanism->pParameter && pMechanism->ulParameterLen >= 16) {
        memcpy(s->encrypt_iv, pMechanism->pParameter, 16);
    } else {
        memset(s->encrypt_iv, 0, 16);
    }
    return CKR_OK;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen) {
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    session_state_t* s = get_session(hSession);
    if (!s) return CKR_SESSION_HANDLE_INVALID;
    if (s->encrypt_key == 0) return CKR_OPERATION_NOT_INITIALIZED;
    if (!pData || !pulEncryptedDataLen) return CKR_ARGUMENTS_BAD;

    if (ulDataLen > HSM_MAX_PAYLOAD_SIZE - 16) {
        return CKR_DATA_LEN_RANGE;
    }

    if (!pEncryptedData) {
        *pulEncryptedDataLen = ulDataLen + 16;
        return CKR_OK;
    }

    hsm_req_t req;
    hsm_resp_t resp;
    memset(&req, 0, sizeof(hsm_req_t));

    req.cmd_id = HSM_CMD_ENCRYPT;
    req.key_handle = (uint32_t)s->encrypt_key;
    memcpy(req.iv, s->encrypt_iv, 16);
    req.in_data_len = (uint32_t)ulDataLen;
    memcpy(req.in_data, pData, ulDataLen);

    if (hsm_host_send_command(&req, &resp) != 0 || resp.status != HSM_STATUS_OK) {
        if (resp.status == HSM_STATUS_ERR_INVALID_HANDLE) return CKR_OBJECT_HANDLE_INVALID;
        return CKR_FUNCTION_FAILED;
    }

    if (*pulEncryptedDataLen < resp.out_data_len) {
        *pulEncryptedDataLen = resp.out_data_len;
        return CKR_BUFFER_TOO_SMALL;
    }

    memcpy(pEncryptedData, resp.out_data, resp.out_data_len);
    *pulEncryptedDataLen = resp.out_data_len;
    s->encrypt_key = 0; // Operation completed
    return CKR_OK;
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    session_state_t* s = get_session(hSession);
    if (!s) return CKR_SESSION_HANDLE_INVALID;
    if (!pMechanism) return CKR_ARGUMENTS_BAD;
    if (pMechanism->mechanism != CKM_AES_CBC_PAD) return CKR_MECHANISM_INVALID;

    s->decrypt_key = hKey;
    if (pMechanism->pParameter && pMechanism->ulParameterLen >= 16) {
        memcpy(s->decrypt_iv, pMechanism->pParameter, 16);
    } else {
        memset(s->decrypt_iv, 0, 16);
    }
    return CKR_OK;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
                CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) {
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    session_state_t* s = get_session(hSession);
    if (!s) return CKR_SESSION_HANDLE_INVALID;
    if (s->decrypt_key == 0) return CKR_OPERATION_NOT_INITIALIZED;
    if (!pEncryptedData || !pulDataLen) return CKR_ARGUMENTS_BAD;

    if (ulEncryptedDataLen > HSM_MAX_PAYLOAD_SIZE) {
        return CKR_DATA_LEN_RANGE;
    }

    if (!pData) {
        *pulDataLen = ulEncryptedDataLen;
        return CKR_OK;
    }

    hsm_req_t req;
    hsm_resp_t resp;
    memset(&req, 0, sizeof(hsm_req_t));

    req.cmd_id = HSM_CMD_DECRYPT;
    req.key_handle = (uint32_t)s->decrypt_key;
    memcpy(req.iv, s->decrypt_iv, 16);
    req.in_data_len = (uint32_t)ulEncryptedDataLen;
    memcpy(req.in_data, pEncryptedData, ulEncryptedDataLen);

    if (hsm_host_send_command(&req, &resp) != 0 || resp.status != HSM_STATUS_OK) {
        if (resp.status == HSM_STATUS_ERR_INVALID_HANDLE) return CKR_OBJECT_HANDLE_INVALID;
        return CKR_FUNCTION_FAILED;
    }

    if (*pulDataLen < resp.out_data_len) {
        *pulDataLen = resp.out_data_len;
        return CKR_BUFFER_TOO_SMALL;
    }

    memcpy(pData, resp.out_data, resp.out_data_len);
    *pulDataLen = resp.out_data_len;
    s->decrypt_key = 0; // Operation completed
    return CKR_OK;
}

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism) {
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    session_state_t* s = get_session(hSession);
    if (!s) return CKR_SESSION_HANDLE_INVALID;
    if (!pMechanism) return CKR_ARGUMENTS_BAD;
    if (pMechanism->mechanism != CKM_SHA256) return CKR_MECHANISM_INVALID;

    s->digest_mech = pMechanism->mechanism;
    s->digest_active = 1;
    return CKR_OK;
}

CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
               CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    session_state_t* s = get_session(hSession);
    if (!s) return CKR_SESSION_HANDLE_INVALID;
    if (!s->digest_active) return CKR_OPERATION_NOT_INITIALIZED;
    if (!pData || !pulDigestLen) return CKR_ARGUMENTS_BAD;

    if (!pDigest) {
        *pulDigestLen = 32;
        return CKR_OK;
    }

    if (*pulDigestLen < 32) {
        *pulDigestLen = 32;
        return CKR_BUFFER_TOO_SMALL;
    }

    hsm_req_t req;
    hsm_resp_t resp;
    memset(&req, 0, sizeof(hsm_req_t));

    req.cmd_id = HSM_CMD_DIGEST;
    req.in_data_len = (uint32_t)ulDataLen;
    memcpy(req.in_data, pData, ulDataLen);

    if (hsm_host_send_command(&req, &resp) != 0 || resp.status != HSM_STATUS_OK) {
        return CKR_FUNCTION_FAILED;
    }

    memcpy(pDigest, resp.out_data, 32);
    *pulDigestLen = 32;
    s->digest_active = 0;
    return CKR_OK;
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    session_state_t* s = get_session(hSession);
    if (!s) return CKR_SESSION_HANDLE_INVALID;
    if (!pMechanism) return CKR_ARGUMENTS_BAD;
    if (pMechanism->mechanism != CKM_SHA256_HMAC && pMechanism->mechanism != CKM_EDDSA) {
        return CKR_MECHANISM_INVALID;
    }

    s->sign_key = hKey;
    return CKR_OK;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
             CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    session_state_t* s = get_session(hSession);
    if (!s) return CKR_SESSION_HANDLE_INVALID;
    if (s->sign_key == 0) return CKR_OPERATION_NOT_INITIALIZED;
    if (!pData || !pulSignatureLen) return CKR_ARGUMENTS_BAD;

    hsm_req_t req;
    hsm_resp_t resp;
    memset(&req, 0, sizeof(hsm_req_t));

    req.cmd_id = HSM_CMD_SIGN;
    req.key_handle = (uint32_t)s->sign_key;
    req.in_data_len = (uint32_t)ulDataLen;
    memcpy(req.in_data, pData, ulDataLen);

    if (hsm_host_send_command(&req, &resp) != 0 || resp.status != HSM_STATUS_OK) {
        if (resp.status == HSM_STATUS_ERR_INVALID_HANDLE) return CKR_OBJECT_HANDLE_INVALID;
        return CKR_FUNCTION_FAILED;
    }

    if (!pSignature) {
        *pulSignatureLen = resp.out_data_len;
        return CKR_OK;
    }

    if (*pulSignatureLen < resp.out_data_len) {
        *pulSignatureLen = resp.out_data_len;
        return CKR_BUFFER_TOO_SMALL;
    }

    memcpy(pSignature, resp.out_data, resp.out_data_len);
    *pulSignatureLen = resp.out_data_len;
    s->sign_key = 0;
    return CKR_OK;
}

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    session_state_t* s = get_session(hSession);
    if (!s) return CKR_SESSION_HANDLE_INVALID;
    if (!pMechanism) return CKR_ARGUMENTS_BAD;
    if (pMechanism->mechanism != CKM_SHA256_HMAC && pMechanism->mechanism != CKM_EDDSA) {
        return CKR_MECHANISM_INVALID;
    }

    s->verify_key = hKey;
    return CKR_OK;
}

CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
               CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    session_state_t* s = get_session(hSession);
    if (!s) return CKR_SESSION_HANDLE_INVALID;
    if (s->verify_key == 0) return CKR_OPERATION_NOT_INITIALIZED;
    if (!pData || !pSignature) return CKR_ARGUMENTS_BAD;

    hsm_req_t req;
    hsm_resp_t resp;
    memset(&req, 0, sizeof(hsm_req_t));

    req.cmd_id = HSM_CMD_VERIFY;
    req.key_handle = (uint32_t)s->verify_key;

    if (ulSignatureLen == 32) {
        // HMAC-SHA256
        memcpy(req.iv, pSignature, 32);
        req.in_data_len = (uint32_t)ulDataLen;
        memcpy(req.in_data, pData, ulDataLen);
    } else if (ulSignatureLen == 64) {
        // Ed25519: [Signature: 64 bytes][Message: ulDataLen]
        memcpy(req.in_data, pSignature, 64);
        memcpy(req.in_data + 64, pData, ulDataLen);
        req.in_data_len = 64 + (uint32_t)ulDataLen;
    } else {
        return CKR_SIGNATURE_LEN_RANGE;
    }

    if (hsm_host_send_command(&req, &resp) != 0) {
        return CKR_FUNCTION_FAILED;
    }

    s->verify_key = 0;
    if (resp.status == HSM_STATUS_OK) {
        return CKR_OK;
    } else if (resp.status == HSM_STATUS_ERR_INVALID_HANDLE) {
        return CKR_OBJECT_HANDLE_INVALID;
    } else {
        return CKR_SIGNATURE_INVALID;
    }
}
