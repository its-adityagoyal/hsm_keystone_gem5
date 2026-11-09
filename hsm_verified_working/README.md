# HSM Enclave Source Code

Hardware Security Module implementation running inside Keystone TEE on RISC-V.

## Files

| File | Description |
|------|-------------|
| `hsm_protocol.h` | IPC command IDs, key types, usage flags, error codes, request/response packets |
| `hsm_eapp.c` | Enclave app: secure command loop processing HSM requests |
| `hsm_host.h / .cpp` | Host-side enclave manager + 8-test verification suite |
| `key_store.h / .c` | Protected key slot table (64 slots, opaque handles, zeroization) |
| `crypto_aes.h / .c` | AES-128/256 CBC with PKCS#7 padding |
| `crypto_sha256.h / .c` | SHA-256 digest + HMAC-SHA256 message authentication |
| `crypto_prng.h / .c` | PRNG seeded from RISC-V rdcycle + SHA-256 counter DRBG |
| `pkcs11.h` | Standard PKCS #11 function prototypes |
| `pkcs11_types.h` | PKCS #11 type definitions and mechanisms |
| `pkcs11_keystone.c` | PKCS #11 API implementation over Keystone HSM |
| `test_pkcs11_hsm.c` | Standalone PKCS #11 test application |
| `start.S` | Enclave entry point (_start calls main, jumps to EAPP_RETURN) |
| `CMakeLists.txt` | Keystone SDK build config |
| `run_hsm.py` | gem5 Full System simulation configuration |

## Supported Operations

- **AES-256**: Key generation, CBC encryption/decryption with PKCS#7 padding
- **SHA-256**: FIPS 180-4 message digest
- **HMAC-SHA256**: RFC 2104 message authentication (sign + verify)
- **Key Lifecycle**: Generation, secure destruction with zeroization
- **Security Boundary**: Invalid/forged handle rejection

## Test Results: 8/8 PASS (100%)
