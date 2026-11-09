# HSM on RISC-V Keystone TEE

A freestanding **Hardware Security Module (HSM)** running inside a [Keystone TEE](https://keystone-enclave.org/) enclave on RISC-V. Cryptographic services are exposed through an 18-function **PKCS #11 (Cryptoki v2.40)** API. Keys never leave enclave memory — the host only ever sees opaque 32-bit handles.

**Verified on:** QEMU 5.0.0 and gem5 v21.1 (AtomicSimpleCPU) full-system simulation.  
**Test result:** 8/8 PASS.

---

## Architecture

```
┌───────────────────────────── Host (Linux, RISC-V) ─────────────────────────────┐
│  test_pkcs11_hsm.c  ──PKCS#11 calls──►  pkcs11_keystone.c                      │
│                                               │                                 │
│                                        hsm_host_bridge.cpp                      │
│                                   (enclave lifecycle + pthread sync)             │
└───────────────────────────────────────────────┼────────────────────────────────┘
                                                │  OCALL_HSM_DISPATCH (edge call)
                            ════════════ PMP Security Boundary ══════════════
┌───────────────────────── Enclave (Keystone + Eyrie runtime) ───────────────────┐
│                              hsm_eapp.c                                         │
│                     (dispatch loop over 64 KB shared buffer)                    │
│                                                                                 │
│   key_store.c        crypto_aes.c       crypto_sha256.c      crypto_prng.c     │
│  (64-slot table)   (AES-256 CBC)       (SHA-256 + HMAC)    (SHA-256 DRBG)      │
└────────────────────────────────────────────────────────────────────────────────┘
```

Communication uses a 64 KB shared buffer and a single edge call (`OCALL_HSM_DISPATCH = 5`). The wire format is defined in `hsm_protocol.h` (`hsm_req_t` / `hsm_resp_t`).

---

## Supported Operations

| Operation | Mechanism | Standard |
|-----------|-----------|----------|
| AES-256 key generation | CKM_AES_KEY_GEN | PKCS #11 |
| AES-256 CBC encryption | CKM_AES_CBC_PAD | FIPS 197 + PKCS#7 |
| AES-256 CBC decryption | CKM_AES_CBC_PAD | FIPS 197 + PKCS#7 |
| SHA-256 digest | CKM_SHA256 | FIPS 180-4 |
| HMAC-SHA256 sign | CKM_SHA256_HMAC | RFC 2104 |
| HMAC-SHA256 verify | CKM_SHA256_HMAC | RFC 2104 |
| Key destruction | C_DestroyObject | PKCS #11 |

---

## Test Suite — 8/8 PASS

| # | Test | Result |
|---|------|--------|
| 1 | AES-256 key generation | PASS |
| 2 | AES-256 CBC encryption | PASS |
| 3 | AES-256 CBC decryption (round-trip) | PASS |
| 4 | SHA-256 hash | PASS |
| 5 | HMAC-SHA256 sign | PASS |
| 6 | HMAC verify + tamper detection | PASS |
| 7 | Security boundary — forged handle rejected | PASS |
| 8 | Key destruction + post-destroy access denied | PASS |

---

## Repository Layout

```
hsm/
├── hsm_eapp.c            # Enclave application — command dispatch loop
├── hsm_host_bridge.cpp   # Host bridge — enclave lifecycle, pthread sync, OCALL
├── pkcs11_keystone.c     # PKCS #11 API layer (18 Cryptoki functions)
├── test_pkcs11_hsm.c     # Test harness — 8 tests, pure PKCS #11 calls
├── hsm_protocol.h        # Wire format: hsm_req_t / hsm_resp_t, command IDs
├── crypto_aes.c/.h       # AES-256 (FIPS 197) + CBC mode + PKCS#7 padding
├── crypto_sha256.c/.h    # SHA-256 (FIPS 180-4) + HMAC-SHA256 (RFC 2104)
├── crypto_prng.c/.h      # Counter-based SHA-256 DRBG seeded from rdcycle
├── key_store.c/.h        # 64-slot key table, opaque handles (base 0x1000)
├── pkcs11.h              # Standard PKCS #11 function prototypes
├── pkcs11_types.h        # PKCS #11 type/mechanism definitions
├── hsm_host.h/.cpp       # Host-side enclave manager
├── keystone_syscalls.c/.h# RISC-V Keystone syscall wrappers
├── start.S               # Enclave entry point (_start → main → EAPP_RETURN)
├── app.lds               # Linker script (freestanding, -nostdlib, 30 KB)
├── CMakeLists.txt        # Build config — static link against Keystone SDK
└── run_hsm.py            # gem5 full-system simulation script
```

---

## Build Requirements

- **Keystone SDK** — cloned and built at `/data/users/aditya/keystone/`
- **RISC-V cross-toolchain** — `riscv64-unknown-linux-gnu-gcc` (from Keystone buildroot)
- **CMake ≥ 3.10**
- The enclave binary is **freestanding** (`-nostdlib -static -T app.lds`): no glibc, no `/dev/urandom`, no dynamic linking.

---

## Build & Run

### 1. Set up the Keystone environment

```bash
cd /data/users/aditya/keystone
source source.sh
```

### 2. Build

```bash
cd build
make examples
```

This produces three artifacts:
- `build/examples/hsm/hsm-eapp` — enclave binary (~30 KB)
- `build/examples/hsm/test_pkcs11_hsm` — host test runner
- `build/examples/hsm/eyrie-rt` — Eyrie runtime

### 3. Inject into rootfs (debugfs)

```bash
debugfs -w rootfs.ext2 <<EOF
rm /root/hsm-eapp
write build/examples/hsm/hsm-eapp /root/hsm-eapp
set_inode_field /root/hsm-eapp mode 0100755
rm /root/test_pkcs11_hsm
write build/examples/hsm/test_pkcs11_hsm /root/test_pkcs11_hsm
set_inode_field /root/test_pkcs11_hsm mode 0100755
EOF
```

### 4. Run on QEMU

```bash
~/run_qemu.sh
# Inside QEMU guest:
./test_pkcs11_hsm ./hsm-eapp ./eyrie-rt
# Expected: 8/8 PASS
```

### 5. Run on gem5 (cycle-accurate)

```bash
~/run_gem5_sim.sh
# Uses AtomicSimpleCPU; O3 not recommended (12-24h boot time)
```

---

## Key Design Decisions

**Why freestanding?**  
The Keystone SDK's host libraries lack `-fPIC`, so everything must be statically linked. The enclave itself uses a custom linker script (`app.lds`) and entry point (`start.S`) with no libc dependency.

**Why SHA-256 DRBG?**  
No `/dev/urandom` inside an enclave. The PRNG seeds from `rdcycle` (RISC-V cycle counter) and runs a counter-based SHA-256 DRBG, keeping the enclave self-contained.

**Why opaque handles?**  
Key material never crosses the PMP boundary. The host receives a 32-bit handle (base `0x1000`) and passes it back for every operation. The key store validates handles before use and zeroes key slots on destruction.

---

## Author

**Aditya Goyal** (23EC30067)  
Dept. of Electronics & Electrical Communication Engineering, IIT Kharagpur  
BTP Supervisor: Prof. Sarani Bhattacharya
