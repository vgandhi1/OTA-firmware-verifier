# OTA Verifier

Simulated secure boot and OTA firmware verifier: a host-side **firmware signer** and a device-side **secure bootloader** that verify integrity and authenticity of firmware images and enforce anti-rollback protection.

See [architecture.md](architecture.md) and [planning.md](planning.md) for design details and development phases.

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

Clone or enter the workspace, then build all crates:

```bash
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
| `secret.key` | 32-byte Ed25519 private key | Signing host / CI secret |
| `public.key` | 32-byte Ed25519 public key | Burned into the bootloader |

> **Security note:** Keep `secret.key` out of version control. Add it to `.gitignore`.

---

### 2. Sign a firmware payload

Produce a signed image from a raw `.bin` payload. The version number must be monotonically increasing for anti-rollback to work.

> **Note:** `--payload` must point to an existing file. If you just want to test the pipeline, create a dummy payload first:
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

The signed image has the following header layout:

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

Run the secure bootloader against the signed image. Supply the public key that corresponds to the signing key used above.

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

The bootloader reads an optional `stored_version.txt` file in the current directory. If the file is present and its integer value is greater than the image version, the boot is rejected.

```bash
# Simulate stored version = 2
echo "2" > stored_version.txt

# This will be rejected because version 1 < stored version 2
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
OTA-verifier/
├── Cargo.toml              # Workspace manifest
├── firmware_signer/        # Host-side signing tool (keygen + sign)
│   ├── Cargo.toml
│   └── src/main.rs
├── secure_bootloader/      # Device-side verifier / bootloader
│   ├── Cargo.toml
│   └── src/main.rs
├── integration_tests/      # End-to-end test suite
│   ├── Cargo.toml
│   └── src/lib.rs
├── architecture.md         # System design and header format
├── planning.md             # Development phases and roadmap
└── TECH_STACK.md           # Technology choices and rationale
```
