# OTA Firmware Verifier

A simulated secure boot and OTA firmware verification system built in Rust. Models the cryptographic pipeline used in production automotive ECUs: a host-side **firmware signer** and a device-side **secure bootloader** that verify firmware integrity and authenticity, and enforce anti-rollback protection.

> **Disclaimer:** This is a proof-of-concept simulation for educational and portfolio purposes. It models real-world automotive security patterns but does not run on embedded hardware.

---

## Motivation

Modern vehicles contain dozens of ECUs that receive over-the-air firmware updates. Without cryptographic verification, an attacker who can reach the OTA channel — or who plugs into a diagnostic port — can flash arbitrary code onto safety-critical systems. Regulations such as **UNECE WP.29/R156** and the **ISO/SAE 21434** standard now mandate that OEMs implement secure software update mechanisms with integrity verification and rollback prevention.

This project models that pipeline end-to-end: signing firmware with an OEM private key, embedding the signature in a structured binary image, and verifying that image in the bootloader before allowing execution.

---

## Security Model

### Threat model

| Threat | Attack scenario | Mitigation |
|---|---|---|
| **Malicious firmware flash** | Attacker loads unsigned firmware via a diagnostic port | Bootloader rejects — attacker lacks the OEM private key to produce a valid signature |
| **OTA tampering** | Firmware is altered in transit over the air | A single changed byte invalidates the SHA-256 hash, causing Ed25519 verification to fail |
| **Version downgrade** | Attacker re-flashes an older signed image containing known CVEs | Bootloader checks the image `VERSION` field against a stored monotonic counter and rejects downgrades |

### Trust model

```
OEM Signing Host
  └── secret.key (Ed25519 private key — never leaves signing host)
        └── Signs firmware payload → firmware.signed.bin
              └── Verified by secure_bootloader using public.key
                    (public key is burned into the bootloader at build time)
```

### Cryptographic choices

- **Ed25519 (EdDSA / Curve25519)** — fast, 64-byte signatures, resistant to side-channel attacks
- **SHA-256** — payload is hashed before signing
- **Rust + `ed25519-dalek` + `sha2`** — memory-safe implementation; no buffer overflows during header parsing

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Build](#build)
- [Usage](#usage)
  - [1. Generate a keypair](#1-generate-a-keypair)
  - [2. Sign a firmware payload](#2-sign-a-firmware-payload)
  - [3. Verify and boot](#3-verify-and-boot)
  - [4. Anti-rollback enforcement](#4-anti-rollback-enforcement)
- [Running Tests](#running-tests)
- [Project Structure](#project-structure)

---

## Prerequisites

- **Rust (stable)** — version 1.60 or later recommended.

---

## Installation

### Install Rust via rustup (recommended)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

Verify the installation:

```bash
rustc --version
cargo --version
```

### Alternative — system package

```bash
# Ubuntu / Debian
sudo apt install cargo

# Fedora
sudo dnf install cargo
```

> **Note:** The system package may be an older version. `rustup` is preferred.

---

## Build

Clone the repository and build all crates:

```bash
git clone https://github.com/vgandhi1/ota-firmware-verifier.git
cd ota-firmware-verifier
cargo build --workspace
```

For a release build (optimised, smaller binary):

```bash
cargo build --workspace --release
```

Compiled binaries land in:

| Binary | Location |
|---|---|
| `firmware_signer` | `target/debug/firmware_signer` |
| `secure_bootloader` | `target/debug/secure_bootloader` |

---

## Usage

### 1. Generate a keypair

Run this **once** on the signing host or in CI to produce an Ed25519 keypair.

```bash
cargo run -p firmware_signer -- keygen \
  --secret secret.key \
  --public public.key
```

| File | Contents | Who holds it |
|---|---|---|
| `secret.key` | 32-byte Ed25519 private key | Signing host / CI secret — never commit |
| `public.key` | 32-byte Ed25519 public key | Burned into the bootloader |

> Both files are excluded by `.gitignore`. Do not commit `secret.key` under any circumstances.

---

### 2. Sign a firmware payload

Produce a signed image from a raw `.bin` payload. The version number must be monotonically increasing for anti-rollback to work.

> **Note:** Create a dummy payload if you don't have one:
> ```bash
> dd if=/dev/urandom of=firmware.bin bs=256 count=1
> ```

```bash
cargo run -p firmware_signer -- sign \
  --payload firmware.bin \
  --version 1 \
  --key secret.key \
  --output firmware.signed.bin
```

The signed image uses the following header layout:

```
Offset  Size  Field
0x00    4     Magic ("SBOT")
0x04    4     Version (u32 LE)
0x08    4     Payload size (u32 LE)
0x0C    64    Ed25519 signature over SHA-256(payload)
0x4C    …     Raw firmware payload
```

---

### 3. Verify and boot

Run the secure bootloader against the signed image. Supply the public key that was generated in step 1.

```bash
cargo run -p secure_bootloader -- \
  --image firmware.signed.bin \
  --public-key public.key
```

**Expected output:**

| Outcome | Message | Exit code |
|---|---|---|
| Valid signature, version OK | `[SUCCESS] Booting image...` | `0` |
| Invalid magic | `[FATAL] Invalid magic; not a signed SBOT image.` | `1` |
| Signature mismatch | `[FATAL] Signature mismatch. Halting.` | `1` |
| Version downgrade | `[FATAL] Version downgrade rejected. Halting.` | `1` |
| Truncated image | `[FATAL] Image truncated: payload size exceeds file length.` | `1` |

---

### 4. Anti-rollback enforcement

The bootloader reads an optional `stored_version.txt` in the current directory. If present and its value exceeds the image version, the boot is rejected.

```bash
# Simulate stored version = 2
echo "2" > stored_version.txt

# Rejected — image version 1 < stored version 2
cargo run -p secure_bootloader -- \
  --image firmware.signed.bin \
  --public-key public.key
# [FATAL] Version downgrade rejected. Halting.

# Sign a newer image and it will pass
cargo run -p firmware_signer -- sign \
  --payload firmware.bin --version 3 \
  --key secret.key --output firmware_v3.signed.bin

cargo run -p secure_bootloader -- \
  --image firmware_v3.signed.bin \
  --public-key public.key
# [SUCCESS] Booting image...
```

If `stored_version.txt` does not exist, the stored version defaults to `0` and any version is accepted.

---

## Running Tests

```bash
cargo test --workspace
```

The `integration_tests` crate exercises four scenarios end-to-end:

| Test | Description |
|---|---|
| `golden_path` | Signs a valid image, verifies with the matching key → success |
| `tamper` | Flips one bit in the payload after signing → bootloader rejects |
| `key_mismatch` | Signs with key A, verifies with key B → rejection |
| `downgrade` | Stored version is 2, image version is 1 → rejection |

---

## Project Structure

```
ota-firmware-verifier/
├── Cargo.toml                    # Workspace manifest
├── Cargo.lock                    # Pinned dependency versions
├── firmware_signer/              # Host-side signing tool (keygen + sign)
│   ├── Cargo.toml
│   └── src/main.rs
├── secure_bootloader/            # Device-side verifier / bootloader
│   ├── Cargo.toml
│   └── src/main.rs
├── integration_tests/            # End-to-end test suite
│   ├── Cargo.toml
│   └── src/lib.rs
├── architecture.md               # System design and binary header format
├── planning.md                   # Development phases and roadmap
└── TECH_STACK.md                 # Technology choices and rationale
```

---

## Related Standards

- **UNECE WP.29 / R156** — UN regulation mandating software update management systems for road vehicles
- **ISO/SAE 21434** — Road vehicle cybersecurity engineering standard covering OTA security requirements
