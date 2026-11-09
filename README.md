# HSM on RISC-V Keystone TEE

**BTP Project — IIT Kharagpur**  
Aditya Goyal (23EC30067) · Dept. of Electronics & Electrical Communication Engineering  
Supervisor: Prof. Sarani Bhattacharya

---

A freestanding **Hardware Security Module (HSM)** running inside a [Keystone TEE](https://keystone-enclave.org/) enclave on RISC-V. Cryptographic services are exposed through an 18-function **PKCS #11 (Cryptoki v2.40)** API. Keys never leave enclave memory — the host only ever sees opaque 32-bit handles.

**Verified on:** QEMU 5.0.0 · gem5 v21.1 (AtomicSimpleCPU)  
**Test result: 8/8 PASS**

---

## Repository Layout

```
├── hsm/                     # HSM source code (latest)
├── hsm_verified_working/    # Snapshot — the exact code that produced 8/8 PASS
├── logs/                    # gem5 stats, QEMU output, simulation terminal logs
├── MASTER_REFERENCE.md      # Complete reference: build steps, architecture, all commands
└── CRYPTO_OPERATIONS.md     # Detailed cryptographic algorithm documentation
```

---

## Architecture

```
┌───────────────────────────── Host (Linux, RISC-V) ─────────────────────────────┐
│  test_pkcs11_hsm.c  ──PKCS#11 calls──►  pkcs11_keystone.c                      │
│                                               │                                 │
│                                        hsm_host_bridge.cpp                      │
│                                   (enclave lifecycle + pthread sync)             │
└───────────────────────────────────────────────┼────────────────────────────────┘
                                                │  OCALL_HSM_DISPATCH = 5
                            ════════════ PMP Security Boundary ════════════
┌───────────────────────── Enclave (Keystone + Eyrie runtime) ───────────────────┐
│                              hsm_eapp.c                                         │
│                     (dispatch loop over 64 KB shared buffer)                    │
│                                                                                 │
│   key_store.c        crypto_aes.c       crypto_sha256.c      crypto_prng.c     │
│  (64-slot table)   (AES-256 CBC)       (SHA-256 + HMAC)    (SHA-256 DRBG)      │
└────────────────────────────────────────────────────────────────────────────────┘
```

---

## Cryptographic Operations

| Operation | Mechanism | Standard |
|-----------|-----------|----------|
| AES-256 key generation | CKM_AES_KEY_GEN | PKCS #11 |
| AES-256 CBC encryption | CKM_AES_CBC_PAD | FIPS 197 + PKCS#7 |
| AES-256 CBC decryption | CKM_AES_CBC_PAD | FIPS 197 + PKCS#7 |
| SHA-256 digest | CKM_SHA256 | FIPS 180-4 |
| HMAC-SHA256 sign | CKM_SHA256_HMAC | RFC 2104 |
| HMAC-SHA256 verify | CKM_SHA256_HMAC | RFC 2104 |
| Key destruction (zeroize) | C_DestroyObject | PKCS #11 |

---

## Test Suite — 8/8 PASS

| # | Test | Result |
|---|------|--------|
| 1 | AES-256 key generation | ✅ PASS |
| 2 | AES-256 CBC encryption | ✅ PASS |
| 3 | AES-256 CBC decryption (round-trip) | ✅ PASS |
| 4 | SHA-256 hash | ✅ PASS |
| 5 | HMAC-SHA256 sign | ✅ PASS |
| 6 | HMAC verify + tamper detection | ✅ PASS |
| 7 | Security boundary — forged handle rejected | ✅ PASS |
| 8 | Key destruction + post-destroy access denied | ✅ PASS |

---

## Dependencies

This project builds against the **Keystone SDK**. Set it up first:

```bash
# Clone and build Keystone (RISC-V cross-toolchain required)
git clone https://github.com/keystone-enclave/keystone.git
cd keystone
git submodule update --init
mkdir build && cd build
cmake .. -DLINUX_SOURCES=ON
make
source ../source.sh
```

Refer to [Keystone's official documentation](https://docs.keystone-enclave.org/) for full setup.

---

## Build & Run

### 1. Set up environment

```bash
cd /path/to/keystone
source source.sh
```

### 2. Copy HSM source into Keystone examples

```bash
cp -r hsm/ keystone/sdk/examples/hsm/
```

### 3. Build

```bash
cd keystone/build
make examples
# Produces: hsm-eapp, test_pkcs11_hsm, eyrie-rt
```

### 4. Inject into rootfs

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

### 5. Run on QEMU

```bash
# Boot QEMU with the Keystone RISC-V image
./scripts/run_qemu.sh

# Inside the QEMU guest:
./test_pkcs11_hsm ./hsm-eapp ./eyrie-rt
# Expected output: 8/8 PASS
```

### 6. Run on gem5 (cycle-accurate)

```bash
./scripts/run_gem5_sim.sh
# Uses AtomicSimpleCPU; O3 not recommended (12-24h boot time)
```

Detailed commands and paths are documented in [`MASTER_REFERENCE.md`](MASTER_REFERENCE.md).

---

## Simulation Results

Output logs from verified runs are in [`logs/`](logs/):

| File | Contents |
|------|----------|
| `qemu_output.log` | Full QEMU terminal output showing 8/8 PASS |
| `gem5_terminal.log` | gem5 simulation terminal output |
| `gem5_stats.txt` | gem5 performance statistics |
| `gem5_hsm.log` | gem5 simulation run log |

---

## Key Design Notes

- **Freestanding enclave:** `-nostdlib -static -T app.lds`. No glibc, no `/dev/urandom`, no dynamic linking. Custom entry point in `start.S`.
- **PRNG:** Seeds from RISC-V `rdcycle` counter, runs a counter-based SHA-256 DRBG.
- **Key handles:** 32-bit opaque handles (base `0x1000`). Key material never crosses the PMP boundary.
- **Host SDK:** Keystone host libraries lack `-fPIC`, so everything is statically linked.
