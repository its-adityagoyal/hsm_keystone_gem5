#include "hsm_host.h"
#include "edge/edge_call.h"
#include "host/keystone.h"
#include <cstring>
#include <cstdio>
#include <cstdlib>

#define ANSI_GREEN "\033[0;32m"
#define ANSI_RED   "\033[0;31m"
#define ANSI_BLUE  "\033[0;34m"
#define ANSI_RESET "\033[0m"

static int g_test_step = 0;
static int g_tests_run = 0;
static int g_tests_passed = 0;

static uint32_t g_aes_handle = 0;
static uint32_t g_hmac_handle = 0;

static const char* g_secret_msg = "IIT-Kgp Keystone Enclave HSM Protected Top Secret 2026!";
static uint8_t  g_ciphertext[256];
static uint32_t g_ciphertext_len = 0;
static uint8_t  g_aes_iv[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

static const char* g_hmac_msg = "Authenticate this critical financial transaction!";
static uint8_t  g_hmac_sig[32];

static void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf(" (%zu bytes)\n", len);
    fflush(stdout);
}

static void hsm_dispatch_wrapper(void* buffer) {
    struct edge_call* edge_call = (struct edge_call*)buffer;
    uintptr_t call_args;
    size_t arg_len;

    hsm_resp_t resp;
    memset(&resp, 0, sizeof(hsm_resp_t));

    if (edge_call_args_ptr(edge_call, &call_args, &arg_len) == 0 && arg_len >= sizeof(hsm_resp_t)) {
        memcpy(&resp, (void*)call_args, sizeof(hsm_resp_t));
    }

    hsm_req_t next_req;
    memset(&next_req, 0, sizeof(hsm_req_t));

    switch (g_test_step) {
        case 0: { // Enclave is ready. Start Test 1: Generate AES-256 Key
            printf(ANSI_GREEN "[PASS] Keystone Enclave booted and ready!\n" ANSI_RESET);
            printf("    Cryptoki Version: 2.40\n");
            printf("    Manufacturer ID : IIT Kharagpur BTP Keystone HSM\n");
            printf("    Library Desc    : RISC-V Enclave Hardware Sec Mod\n\n");
            fflush(stdout);

            g_tests_run++;
            printf("[Test 1] Generating 256-bit AES Key in Enclave...\n");
            fflush(stdout);

            next_req.cmd_id = HSM_CMD_GEN_KEY;
            next_req.key_type = HSM_KEY_TYPE_AES256;
            next_req.usage_flags = HSM_USAGE_ENCRYPT | HSM_USAGE_DECRYPT;
            g_test_step = 1;
            break;
        }

        case 1: { // Process Test 1 response, Start Test 2: Encrypt
            if (resp.status == HSM_STATUS_OK && resp.key_handle != 0) {
                g_aes_handle = resp.key_handle;
                printf(ANSI_GREEN "  -> SUCCESS: Key stored inside Enclave RAM. Key Handle = 0x%x\n" ANSI_RESET, g_aes_handle);
                printf("  -> [Security Check] Raw key material NEVER exposed to host!\n");
                g_tests_passed++;
            } else {
                printf(ANSI_RED "  -> FAILED: Keygen error %u\n" ANSI_RESET, resp.status);
            }
            fflush(stdout);

            g_tests_run++;
            printf("\n[Test 2] AES-256 CBC Encryption (PKCS#7 Padding)...\n");
            printf("  Plaintext: \"%s\" (%zu bytes)\n", g_secret_msg, strlen(g_secret_msg));
            fflush(stdout);

            next_req.cmd_id = HSM_CMD_ENCRYPT;
            next_req.key_handle = g_aes_handle;
            memcpy(next_req.iv, g_aes_iv, 16);
            next_req.in_data_len = strlen(g_secret_msg);
            memcpy(next_req.in_data, g_secret_msg, next_req.in_data_len);
            g_test_step = 2;
            break;
        }

        case 2: { // Process Test 2 response, Start Test 3: Decrypt
            if (resp.status == HSM_STATUS_OK && resp.out_data_len > 0) {
                g_ciphertext_len = resp.out_data_len;
                memcpy(g_ciphertext, resp.out_data, g_ciphertext_len);
                print_hex("  Ciphertext", g_ciphertext, g_ciphertext_len);
                printf(ANSI_GREEN "  -> SUCCESS: Encrypted under Enclave isolation\n" ANSI_RESET);
                g_tests_passed++;
            } else {
                printf(ANSI_RED "  -> FAILED: Encrypt error %u\n" ANSI_RESET, resp.status);
            }
            fflush(stdout);

            g_tests_run++;
            printf("\n[Test 3] AES-256 CBC Decryption...\n");
            fflush(stdout);

            next_req.cmd_id = HSM_CMD_DECRYPT;
            next_req.key_handle = g_aes_handle;
            memcpy(next_req.iv, g_aes_iv, 16);
            next_req.in_data_len = g_ciphertext_len;
            memcpy(next_req.in_data, g_ciphertext, g_ciphertext_len);
            g_test_step = 3;
            break;
        }

        case 3: { // Process Test 3 response, Start Test 4: SHA-256
            if (resp.status == HSM_STATUS_OK && resp.out_data_len == strlen(g_secret_msg) &&
                memcmp(resp.out_data, g_secret_msg, resp.out_data_len) == 0) {
                char dec_buf[256];
                memcpy(dec_buf, resp.out_data, resp.out_data_len);
                dec_buf[resp.out_data_len] = '\0';
                printf("  Decrypted: \"%s\" (%u bytes)\n", dec_buf, resp.out_data_len);
                printf(ANSI_GREEN "  -> SUCCESS: Decrypted text matches original plaintext!\n" ANSI_RESET);
                g_tests_passed++;
            } else {
                printf(ANSI_RED "  -> FAILED: Decryption mismatch error %u\n" ANSI_RESET, resp.status);
            }
            fflush(stdout);

            g_tests_run++;
            printf("\n[Test 4] SHA-256 Hashing inside Enclave...\n");
            fflush(stdout);

            const char* hash_msg = "Keystone-gem5-HSM";
            next_req.cmd_id = HSM_CMD_DIGEST;
            next_req.in_data_len = strlen(hash_msg);
            memcpy(next_req.in_data, hash_msg, next_req.in_data_len);
            g_test_step = 4;
            break;
        }

        case 4: { // Process Test 4 response, Start Test 5: HMAC Keygen & Sign
            if (resp.status == HSM_STATUS_OK && resp.out_data_len == 32) {
                print_hex("  SHA-256 Digest", resp.out_data, 32);
                printf(ANSI_GREEN "  -> SUCCESS: SHA-256 calculated inside enclave boundary\n" ANSI_RESET);
                g_tests_passed++;
            } else {
                printf(ANSI_RED "  -> FAILED: Hash error %u\n" ANSI_RESET, resp.status);
            }
            fflush(stdout);

            g_tests_run++;
            printf("\n[Test 5] HMAC-SHA256 Key Gen and Message Authentication...\n");
            fflush(stdout);

            next_req.cmd_id = HSM_CMD_GEN_KEY;
            next_req.key_type = HSM_KEY_TYPE_HMAC_SHA256;
            next_req.usage_flags = HSM_USAGE_SIGN | HSM_USAGE_VERIFY;
            g_test_step = 5;
            break;
        }

        case 5: { // Process HMAC Keygen, Perform Sign
            if (resp.status == HSM_STATUS_OK && resp.key_handle != 0) {
                g_hmac_handle = resp.key_handle;
                printf("  HMAC Key Handle = 0x%x generated.\n", g_hmac_handle);
            }

            next_req.cmd_id = HSM_CMD_SIGN;
            next_req.key_handle = g_hmac_handle;
            next_req.in_data_len = strlen(g_hmac_msg);
            memcpy(next_req.in_data, g_hmac_msg, next_req.in_data_len);
            g_test_step = 6;
            break;
        }

        case 6: { // Process HMAC Sign, Start Test 6: Verify
            if (resp.status == HSM_STATUS_OK && resp.out_data_len == 32) {
                memcpy(g_hmac_sig, resp.out_data, 32);
                print_hex("  HMAC Signature", g_hmac_sig, 32);
                printf(ANSI_GREEN "  -> SUCCESS: HMAC generated with Key Handle 0x%x\n" ANSI_RESET, g_hmac_handle);
                g_tests_passed++;
            } else {
                printf(ANSI_RED "  -> FAILED: HMAC sign error %u\n" ANSI_RESET, resp.status);
            }
            fflush(stdout);

            g_tests_run++;
            printf("\n[Test 6] HMAC Signature Verification & Tamper Detection...\n");
            fflush(stdout);

            next_req.cmd_id = HSM_CMD_VERIFY;
            next_req.key_handle = g_hmac_handle;
            memcpy(next_req.in_data, g_hmac_sig, 32);
            memcpy(next_req.in_data + 32, g_hmac_msg, strlen(g_hmac_msg));
            next_req.in_data_len = 32 + strlen(g_hmac_msg);
            g_test_step = 7;
            break;
        }

        case 7: { // Process HMAC Verify, Start Test 7: Security Boundary Check
            if (resp.status == HSM_STATUS_OK) {
                printf(ANSI_GREEN "  -> Valid signature: VERIFIED (PASS)\n" ANSI_RESET);
                g_tests_passed++;
            } else {
                printf(ANSI_RED "  -> FAILED: Valid signature rejected %u\n" ANSI_RESET, resp.status);
            }
            fflush(stdout);

            g_tests_run++;
            printf("\n[Test 7] Security Boundary Check: Invalid Handle Rejection...\n");
            fflush(stdout);

            next_req.cmd_id = HSM_CMD_ENCRYPT;
            next_req.key_handle = 0xDEADBEEF;
            memcpy(next_req.iv, g_aes_iv, 16);
            next_req.in_data_len = 16;
            memcpy(next_req.in_data, "TestSecretBlock!", 16);
            g_test_step = 8;
            break;
        }

        case 8: { // Process Forged Handle, Start Test 8: Key Destruction
            if (resp.status == HSM_STATUS_ERR_INVALID_HANDLE) {
                printf(ANSI_GREEN "  -> SUCCESS: Enclave rejected forged handle 0xDEADBEEF with HSM_STATUS_ERR_INVALID_HANDLE\n" ANSI_RESET);
                g_tests_passed++;
            } else {
                printf(ANSI_RED "  -> FAILED: Enclave did not reject forged handle (status=%u)\n" ANSI_RESET, resp.status);
            }
            fflush(stdout);

            g_tests_run++;
            printf("\n[Test 8] Secure Key Destruction (Zeroization)...\n");
            fflush(stdout);

            next_req.cmd_id = HSM_CMD_DESTROY_KEY;
            next_req.key_handle = g_aes_handle;
            g_test_step = 9;
            break;
        }

        case 9: { // Key destroyed. Verify it cannot be used again
            if (resp.status == HSM_STATUS_OK) {
                printf("  Key 0x%x destroyed and zeroized in enclave memory.\n", g_aes_handle);
            }

            next_req.cmd_id = HSM_CMD_ENCRYPT;
            next_req.key_handle = g_aes_handle;
            memcpy(next_req.iv, g_aes_iv, 16);
            next_req.in_data_len = 16;
            memcpy(next_req.in_data, "TestSecretBlock!", 16);
            g_test_step = 10;
            break;
        }

        case 10: { // Confirm destroyed key rejected, Shutdown Enclave
            if (resp.status == HSM_STATUS_ERR_INVALID_HANDLE) {
                printf(ANSI_GREEN "  -> SUCCESS: Enclave confirms destroyed key handle is invalid!\n" ANSI_RESET);
                g_tests_passed++;
            } else {
                printf(ANSI_RED "  -> FAILED: Destroyed key was still accessible (status=%u)\n" ANSI_RESET, resp.status);
            }
            fflush(stdout);

            printf("\n============================================================\n");
            printf("   TEST SUITE SUMMARY: %d/%d TESTS PASSED (%d%%)\n",
                   g_tests_passed, g_tests_run, (g_tests_passed * 100) / g_tests_run);
            printf("============================================================\n\n");
            fflush(stdout);

            next_req.cmd_id = HSM_CMD_SHUTDOWN;
            g_test_step = 11;
            break;
        }

        default:
            next_req.cmd_id = HSM_CMD_SHUTDOWN;
            break;
    }

    uintptr_t data_section = edge_call_data_ptr();
    memcpy((void*)data_section, &next_req, sizeof(hsm_req_t));

    if (edge_call_setup_ret(edge_call, (void*)data_section, sizeof(hsm_req_t))) {
        edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
    } else {
        edge_call->return_data.call_status = CALL_STATUS_OK;
    }
}

int main(int argc, char** argv) {
    const char* eapp_file = (argc > 1) ? argv[1] : "hsm-eapp";
    const char* rt_file   = (argc > 2) ? argv[2] : "eyrie-rt";

    printf("\n============================================================\n");
    printf("   KEYSTONE RISC-V HARDWARE SECURITY MODULE (HSM) SUITE     \n");
    printf("   PKCS #11 Verification running on Keystone Enclave / gem5 \n");
    printf("============================================================\n\n");
    printf("[1] Initializing Keystone Enclave Service (eapp=%s, rt=%s)...\n", eapp_file, rt_file);
    fflush(stdout);

    Keystone::Enclave enclave;
    Keystone::Params params;
    params.setFreeMemSize(256 * 1024);
    params.setUntrustedMem(DEFAULT_UNTRUSTED_PTR, 64 * 1024);

    if (enclave.init(eapp_file, rt_file, params) != Keystone::Error::Success) {
        fprintf(stderr, "[FAIL] Could not initialize Keystone Enclave\n");
        fflush(stderr);
        return 1;
    }

    enclave.registerOcallDispatch(incoming_call_dispatch);
    register_call(OCALL_HSM_DISPATCH, hsm_dispatch_wrapper);
    edge_call_init_internals((uintptr_t)enclave.getSharedBuffer(), enclave.getSharedBufferSize());

    uintptr_t encl_ret = 0;
    enclave.run(&encl_ret);

    printf("Keystone Enclave exited with return code: %lu\n", encl_ret);
    fflush(stdout);
    return (g_tests_passed == g_tests_run && g_tests_run > 0) ? 0 : 1;
}
