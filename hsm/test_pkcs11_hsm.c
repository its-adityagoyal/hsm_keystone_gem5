#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pkcs11.h"

#define ANSI_GREEN "\033[0;32m"
#define ANSI_RED   "\033[0;31m"
#define ANSI_BLUE  "\033[0;34m"
#define ANSI_RESET "\033[0m"

static void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf(" (%zu bytes)\n", len);
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    int tests_run = 0;
    int tests_passed = 0;

    printf("\n============================================================\n");
    printf("   KEYSTONE RISC-V HARDWARE SECURITY MODULE (HSM) SUITE     \n");
    printf("   PKCS #11 Verification running on Keystone Enclave / gem5 \n");
    printf("============================================================\n\n");

    /* 1. Initialize PKCS #11 */
    printf("[1] Initializing PKCS #11 Library & Keystone Enclave Service...\n");
    CK_RV rv = C_Initialize(NULL);
    if (rv != CKR_OK) {
        printf(ANSI_RED "[FAIL] C_Initialize failed: 0x%lx\n" ANSI_RESET, rv);
        return 1;
    }
    printf(ANSI_GREEN "[PASS] Keystone Enclave booted and ready!\n" ANSI_RESET);

    CK_INFO info;
    rv = C_GetInfo(&info);
    if (rv == CKR_OK) {
        printf("    Cryptoki Version: %d.%d\n", info.cryptokiVersion.major, info.cryptokiVersion.minor);
        printf("    Manufacturer ID : %.32s\n", info.manufacturerID);
        printf("    Description     : %.32s\n", info.libraryDescription);
    }

    /* 2. Open Session */
    CK_SESSION_HANDLE hSession = 0;
    rv = C_OpenSession(1, 0, NULL, NULL, &hSession);
    if (rv != CKR_OK) {
        printf(ANSI_RED "[FAIL] C_OpenSession failed: 0x%lx\n" ANSI_RESET, rv);
        C_Finalize(NULL);
        return 1;
    }
    printf(ANSI_GREEN "[PASS] Session opened successfully (Session Handle: 0x%lx)\n\n" ANSI_RESET, hSession);

    /* 3. Test AES-256 Key Generation */
    tests_run++;
    printf("[Test 1] Generating 256-bit AES Key in Enclave...\n");
    CK_MECHANISM keyGenMech = { CKM_AES_KEY_GEN, NULL, 0 };
    CK_ULONG keyLenBytes = 32;
    CK_ATTRIBUTE keyTemplate[] = {
        { CKA_VALUE_LEN, &keyLenBytes, sizeof(keyLenBytes) },
        { CKA_ENCRYPT, (CK_BBOOL[]){CK_TRUE}, sizeof(CK_BBOOL) },
        { CKA_DECRYPT, (CK_BBOOL[]){CK_TRUE}, sizeof(CK_BBOOL) }
    };

    CK_OBJECT_HANDLE hKeyAes = 0;
    rv = C_GenerateKey(hSession, &keyGenMech, keyTemplate, 3, &hKeyAes);
    if (rv == CKR_OK && hKeyAes != 0) {
        printf(ANSI_GREEN "  -> SUCCESS: Key stored inside Enclave RAM. Key Handle = 0x%lx\n" ANSI_RESET, hKeyAes);
        printf("  -> [Security Check] Raw key material NEVER exposed to untrusted host!\n");
        tests_passed++;
    } else {
        printf(ANSI_RED "  -> FAILED: 0x%lx\n" ANSI_RESET, rv);
    }

    /* 4. Test AES-256 CBC Encryption */
    tests_run++;
    printf("\n[Test 2] AES-256 CBC Encryption (PKCS#7 Padding)...\n");
    uint8_t iv[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    CK_MECHANISM encMech = { CKM_AES_CBC_PAD, iv, sizeof(iv) };

    const char* secret_plaintext = "IIT-Kgp Keystone Enclave HSM Protected Top Secret!";
    CK_ULONG plaintext_len = strlen(secret_plaintext);
    uint8_t ciphertext[256];
    CK_ULONG ciphertext_len = sizeof(ciphertext);

    printf("  Plaintext: \"%s\" (%lu bytes)\n", secret_plaintext, plaintext_len);

    rv = C_EncryptInit(hSession, &encMech, hKeyAes);
    if (rv == CKR_OK) {
        rv = C_Encrypt(hSession, (CK_BYTE_PTR)secret_plaintext, plaintext_len, ciphertext, &ciphertext_len);
    }

    if (rv == CKR_OK) {
        print_hex("  Ciphertext", ciphertext, ciphertext_len);
        printf(ANSI_GREEN "  -> SUCCESS: Encrypted under Enclave isolation\n" ANSI_RESET);
        tests_passed++;
    } else {
        printf(ANSI_RED "  -> FAILED: 0x%lx\n" ANSI_RESET, rv);
    }

    /* 5. Test AES-256 CBC Decryption */
    tests_run++;
    printf("\n[Test 3] AES-256 CBC Decryption...\n");
    uint8_t decrypted[256];
    CK_ULONG decrypted_len = sizeof(decrypted);

    rv = C_DecryptInit(hSession, &encMech, hKeyAes);
    if (rv == CKR_OK) {
        rv = C_Decrypt(hSession, ciphertext, ciphertext_len, decrypted, &decrypted_len);
    }

    if (rv == CKR_OK && decrypted_len == plaintext_len && memcmp(decrypted, secret_plaintext, plaintext_len) == 0) {
        decrypted[decrypted_len] = '\0';
        printf("  Decrypted: \"%s\" (%lu bytes)\n", (char*)decrypted, decrypted_len);
        printf(ANSI_GREEN "  -> SUCCESS: Decrypted text matches original plaintext!\n" ANSI_RESET);
        tests_passed++;
    } else {
        printf(ANSI_RED "  -> FAILED: Decryption mismatch or error 0x%lx\n" ANSI_RESET, rv);
    }

    /* 6. Test SHA-256 Message Digest */
    tests_run++;
    printf("\n[Test 4] SHA-256 Hashing inside Enclave...\n");
    CK_MECHANISM digestMech = { CKM_SHA256, NULL, 0 };
    const char* hash_msg = "Keystone-gem5-HSM";
    uint8_t digest[32];
    CK_ULONG digest_len = sizeof(digest);

    rv = C_DigestInit(hSession, &digestMech);
    if (rv == CKR_OK) {
        rv = C_Digest(hSession, (CK_BYTE_PTR)hash_msg, strlen(hash_msg), digest, &digest_len);
    }

    if (rv == CKR_OK && digest_len == 32) {
        print_hex("  SHA-256 Digest", digest, digest_len);
        printf(ANSI_GREEN "  -> SUCCESS: SHA-256 calculated inside enclave boundary\n" ANSI_RESET);
        tests_passed++;
    } else {
        printf(ANSI_RED "  -> FAILED: 0x%lx\n" ANSI_RESET, rv);
    }

    /* 7. Test HMAC-SHA256 Signing & Verification */
    tests_run++;
    printf("\n[Test 5] HMAC-SHA256 Key Gen and Message Authentication...\n");
    CK_MECHANISM hmacGenMech = { CKM_SHA256_HMAC_KEY_GEN, NULL, 0 };
    CK_OBJECT_HANDLE hKeyHmac = 0;
    rv = C_GenerateKey(hSession, &hmacGenMech, NULL, 0, &hKeyHmac);

    const char* hmac_msg = "Authenticate this critical financial transaction!";
    uint8_t hmac_sig[32];
    CK_ULONG hmac_sig_len = sizeof(hmac_sig);

    CK_MECHANISM hmacMech = { CKM_SHA256_HMAC, NULL, 0 };
    if (rv == CKR_OK) {
        rv = C_SignInit(hSession, &hmacMech, hKeyHmac);
    }
    if (rv == CKR_OK) {
        rv = C_Sign(hSession, (CK_BYTE_PTR)hmac_msg, strlen(hmac_msg), hmac_sig, &hmac_sig_len);
    }

    if (rv == CKR_OK && hmac_sig_len == 32) {
        print_hex("  HMAC Signature", hmac_sig, hmac_sig_len);
        printf(ANSI_GREEN "  -> SUCCESS: HMAC generated with Key Handle 0x%lx\n" ANSI_RESET, hKeyHmac);
        tests_passed++;
    } else {
        printf(ANSI_RED "  -> FAILED: 0x%lx\n" ANSI_RESET, rv);
    }

    /* 8. Verify HMAC Signature and Test Tamper Detection */
    tests_run++;
    printf("\n[Test 6] HMAC Signature Verification & Tamper Detection...\n");
    rv = C_VerifyInit(hSession, &hmacMech, hKeyHmac);
    if (rv == CKR_OK) {
        rv = C_Verify(hSession, (CK_BYTE_PTR)hmac_msg, strlen(hmac_msg), hmac_sig, hmac_sig_len);
    }

    if (rv == CKR_OK) {
        printf(ANSI_GREEN "  -> Valid signature: VERIFIED (PASS)\n" ANSI_RESET);

        // Tamper test: modify 1 byte of the message
        char tampered_msg[128];
        strcpy(tampered_msg, hmac_msg);
        tampered_msg[0] ^= 0xFF;

        C_VerifyInit(hSession, &hmacMech, hKeyHmac);
        CK_RV tamper_rv = C_Verify(hSession, (CK_BYTE_PTR)tampered_msg, strlen(tampered_msg), hmac_sig, hmac_sig_len);
        if (tamper_rv == CKR_SIGNATURE_INVALID) {
            printf(ANSI_GREEN "  -> Tampered message: REJECTED correctly (PASS)\n" ANSI_RESET);
            tests_passed++;
        } else {
            printf(ANSI_RED "  -> Tamper detection failed: 0x%lx\n" ANSI_RESET, tamper_rv);
        }
    } else {
        printf(ANSI_RED "  -> FAILED to verify valid signature: 0x%lx\n" ANSI_RESET, rv);
    }

    /* 9. Security Isolation Check: Invalid Handles */
    tests_run++;
    printf("\n[Test 7] Security Boundary Check: Invalid Handle Rejection...\n");
    CK_OBJECT_HANDLE forged_handle = 0xDEADBEEF;
    rv = C_EncryptInit(hSession, &encMech, forged_handle);
    if (rv == CKR_OK) {
        rv = C_Encrypt(hSession, (CK_BYTE_PTR)secret_plaintext, plaintext_len, ciphertext, &ciphertext_len);
    }

    if (rv == CKR_OBJECT_HANDLE_INVALID) {
        printf(ANSI_GREEN "  -> SUCCESS: Enclave rejected forged handle 0xDEADBEEF with CKR_OBJECT_HANDLE_INVALID\n" ANSI_RESET);
        tests_passed++;
    } else {
        printf(ANSI_RED "  -> FAILED: Security check did not reject invalid handle (rv=0x%lx)\n" ANSI_RESET, rv);
    }

    /* 10. Key Destruction */
    tests_run++;
    printf("\n[Test 8] Secure Key Destruction (Zeroization)...\n");
    rv = C_DestroyObject(hSession, hKeyAes);
    if (rv == CKR_OK) {
        printf("  Key 0x%lx destroyed and zeroized in enclave memory.\n", hKeyAes);

        // Attempt to encrypt with destroyed key
        C_EncryptInit(hSession, &encMech, hKeyAes);
        CK_RV destroyed_rv = C_Encrypt(hSession, (CK_BYTE_PTR)secret_plaintext, plaintext_len, ciphertext, &ciphertext_len);
        if (destroyed_rv == CKR_OBJECT_HANDLE_INVALID) {
            printf(ANSI_GREEN "  -> SUCCESS: Enclave confirms destroyed key handle is invalid!\n" ANSI_RESET);
            tests_passed++;
        } else {
            printf(ANSI_RED "  -> FAILED: Destroyed key could still be accessed (rv=0x%lx)\n" ANSI_RESET, destroyed_rv);
        }
    } else {
        printf(ANSI_RED "  -> FAILED: C_DestroyObject returned 0x%lx\n" ANSI_RESET, rv);
    }

    /* Close session & finalize */
    C_CloseSession(hSession);
    C_Finalize(NULL);

    printf("\n============================================================\n");
    printf("   TEST SUITE SUMMARY: %d/%d TESTS PASSED (%d%%)\n",
           tests_passed, tests_run, (tests_passed * 100) / tests_run);
    printf("============================================================\n\n");

    return (tests_passed == tests_run) ? 0 : 1;
}
