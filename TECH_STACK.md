# Comprehensive Technical Guide
## Embedded Secure Boot & OTA Update Verifier

> **Who this is for:** Someone who is curious about how software works, wants to understand this project fully, but has no background in cybersecurity, cryptography, or embedded systems. Every concept is introduced from first principles, with everyday analogies before any technical depth.

---

## Table of Contents

1. [The Big Picture — What Problem Are We Solving?](#1-the-big-picture)
2. [Background — How Software Gets Into a Car](#2-background-how-software-gets-into-a-car)
3. [What an Attacker Actually Does](#3-what-an-attacker-actually-does)
4. [The Core Concept: Cryptographic Signing](#4-the-core-concept-cryptographic-signing)
5. [Hash Functions — The Fingerprint Machine](#5-hash-functions-the-fingerprint-machine)
6. [Digital Signatures — The Wax Seal](#6-digital-signatures-the-wax-seal)
7. [Ed25519 — The Algorithm We Use](#7-ed25519-the-algorithm-we-use)
8. [The Firmware Image Format — Packaging It All Together](#8-the-firmware-image-format)
9. [Anti-Rollback — Preventing the Time Machine Attack](#9-anti-rollback)
10. [Rust — Why This Language?](#10-rust-why-this-language)
11. [The Two Programs: Signer and Bootloader](#11-the-two-programs)
12. [Walking Through the Code](#12-walking-through-the-code)
13. [The Test Suite — Proving It Works](#13-the-test-suite)
14. [The Threat Model — Thinking Like an Attacker](#14-the-threat-model)
15. [How This Maps to the Real World](#15-how-this-maps-to-the-real-world)
16. [Glossary](#16-glossary)
17. [Further Reading](#17-further-reading)

---

## 1. The Big Picture

### What is firmware?

Your phone runs apps. Your laptop runs Windows or macOS. Your car's brakes, engine, and airbags also run software — but it is called **firmware**. Firmware is software stored permanently in a chip, designed to control hardware directly.

A modern car contains over 100 separate computers called **ECUs** (Electronic Control Units). Each one runs its own firmware:

- The engine control unit manages fuel injection
- The anti-lock braking system (ABS) unit manages wheel lockup prevention
- The airbag controller manages deployment timing
- The infotainment unit manages the touchscreen

Each of these can be updated — either at a dealership via a physical cable, or remotely over the internet (called an **OTA update**, short for "Over-The-Air").

### The problem

If firmware can be updated remotely, then an attacker who intercepts that update can replace it with malicious software. If that malicious software reaches, say, the braking ECU, the consequences are not like a crashed app on your phone — they are physical.

**This project solves that problem.** It builds a system where the car's bootloader (the first program that runs when a chip powers on) can verify, with mathematical certainty, whether a firmware update is genuine before running it.

---

## 2. Background — How Software Gets Into a Car

### The boot process

When any computer — a laptop, a phone, a car ECU — powers on, it doesn't immediately run the main operating system or application. It first runs a small, trusted piece of code called the **bootloader**.

The bootloader's job is simple:
1. Run basic hardware checks
2. Find the main software in storage
3. Load it into memory and run it

In a car ECU, the sequence looks like this:

```
Power on
    ↓
Bootloader runs from ROM (Read-Only Memory — cannot be changed)
    ↓
Bootloader reads firmware image from Flash storage
    ↓
[This is where our verification happens]
    ↓
If firmware is valid → jump to firmware, car feature starts
If firmware is invalid → halt, log error, do not run
```

### Why does the bootloader live in ROM?

ROM (Read-Only Memory) is physically write-protected. An attacker cannot overwrite it even with full access to the device. By placing the bootloader in ROM and hardcoding the OEM's public key into it, we create an **immutable root of trust** — a starting point for security that cannot be tampered with.

### What is Flash memory?

Flash memory is where the actual firmware lives. Unlike ROM, it can be rewritten — that's how OTA updates work. The firmware in Flash is what needs to be verified before each boot.

---

## 3. What an Attacker Actually Does

To understand why the defences in this project are designed the way they are, it helps to understand the three specific attacks it defeats.

### Attack 1: Malicious USB Flash

**Scenario:** A malicious actor gets physical access to a vehicle — at a dealership, a repair shop, or through theft. They connect a laptop to the OBD-II diagnostic port (a standard port present in every car since 1996) and attempt to flash custom firmware.

**What custom firmware can do:**
- Disable safety systems
- Create a backdoor for remote access
- Log location data
- Prevent the brakes from engaging

**Without this project:** If the bootloader runs any firmware it finds in Flash, the attacker succeeds.

**With this project:** The bootloader refuses to run any firmware that doesn't carry a valid signature from the manufacturer.

---

### Attack 2: OTA Tampering (Man-in-the-Middle)

**Scenario:** The manufacturer pushes an OTA update over a cellular network. An attacker intercepts the connection (a "Man-in-the-Middle" attack) and modifies the firmware file before it arrives at the car.

**What they might change:**
- One line of code in the braking firmware to occasionally ignore brake inputs
- A hidden network listener that phones home

**The challenge:** The modification might be tiny — a single byte changed out of millions.

**With this project:** Any modification, no matter how small, changes the SHA-256 hash of the file. Since the hash has changed, the signature (which was made over the original hash) no longer matches. The bootloader detects this and halts.

---

### Attack 3: Version Downgrade

**Scenario:** A security researcher discovers a vulnerability in firmware version 3 of the engine ECU. The manufacturer patches it in version 4. An attacker who knows about the v3 vulnerability tries to re-flash v3 — which is *still legitimately signed by the manufacturer* — to re-expose the bug.

**The challenge:** A simple signature check passes, because the v3 firmware is genuine. The attacker is not forging anything.

**With this project:** The bootloader maintains a version counter that only goes up. Even a perfectly signed v3 image is rejected when the counter says the device has already accepted v4.

---

## 4. The Core Concept: Cryptographic Signing

Before diving into specific algorithms, it helps to understand what "signing" means in a security context.

### The sealed letter analogy

In the physical world, if you want to send a letter and prove it came from you:
1. You write the letter
2. You seal it with a wax seal stamped with your personal signet ring
3. The recipient can verify the seal matches your ring before opening it

Digital signing works the same way:
- The **private key** is the signet ring (kept secret, never shared)
- The **public key** is a description of your ring's pattern (shared with everyone)
- The **signature** is the wax seal pressed on the document

Anyone with your public key can verify your signature. But only you, with your private key, can create a valid one.

### Why can't an attacker just copy the signature?

A digital signature is not a simple stamp that can be photocopied. It is a mathematical value that is **uniquely tied to both the private key and the exact content being signed**. If either changes — the key is different, or even one bit of the content is different — the signature becomes invalid.

More precisely, a digital signature is:

```
signature = private_key_operation(hash_of_document)
```

Verifying it means:
```
valid = public_key_operation(signature) == hash_of_document
```

The mathematics of this is a one-way relationship. Given the public key and a valid signature, you cannot reverse-engineer the private key. The security is guaranteed by the mathematical difficulty of problems like discrete logarithm computation on elliptic curves.

---

## 5. Hash Functions — The Fingerprint Machine

A hash function takes an input of any size and produces a fixed-size output, with three critical properties.

### Property 1: Determinism

The same input always produces the same output.

```
SHA-256("Hello") → 185f8db32921bd46d35cc09...  (always)
SHA-256("Hello") → 185f8db32921bd46d35cc09...  (again, always)
```

### Property 2: The Avalanche Effect

A tiny change in the input completely changes the output.

```
SHA-256("Hello")  → 185f8db32921bd46d35cc09...
SHA-256("Hxllo")  → 08b84b8b66b1e4eb6ff7d38...
                       ↑ completely different
```

This is by mathematical design. Any 1-bit change in the input is supposed to change, on average, half of all output bits. This makes it impossible to make an "undetected" small change to a document.

### Property 3: One-way (Pre-image Resistance)

Given only the hash output, it is computationally infeasible to find the original input.

```
"185f8db32921bd46d35cc09..." → ??? (you cannot reverse this)
```

### Why SHA-256?

SHA-256 produces a 256-bit (32-byte) output. "256-bit security" means that brute-force finding an input that produces a given hash would require 2²⁵⁶ attempts — a number larger than the estimated number of atoms in the observable universe. Even the most powerful computers that will ever be built cannot do this.

### Why hash the firmware before signing?

Ed25519 (the signature algorithm we use) technically works on any message. But firmware files can be hundreds of megabytes. Signing that directly would be slow. By first computing `SHA-256(firmware)` — which is always 32 bytes regardless of firmware size — and then signing *that*, the signing and verification steps are fast and consistent.

---

## 6. Digital Signatures — The Wax Seal

### Asymmetric cryptography (public-key cryptography)

Traditional encryption uses one key for both locking and unlocking (like a house key). **Asymmetric cryptography** uses a matched pair of keys with a special mathematical relationship:

- What the **private key** does, the **public key** can verify
- What the **public key** does, the **private key** can decrypt
- But you **cannot** derive the private key from the public key

This enables digital signatures:

```
[MANUFACTURER]
  private_key (SECRET) ──→ sign(SHA-256(firmware)) ──→ signature

[CAR ECU]
  public_key (hardcoded in ROM) ──→ verify(signature, SHA-256(firmware)) ──→ true/false
```

### The key sizes

In this project:
- **Private key:** 32 bytes (256 bits)
- **Public key:** 32 bytes (256 bits)
- **Signature:** 64 bytes (512 bits)

These are remarkably small. RSA — an older algorithm — needs 256-byte keys and 256-byte signatures for equivalent security. This matters enormously in embedded systems where every byte of storage costs money and every CPU cycle costs power.

### Security model assumptions

The entire system rests on one assumption: **the private key remains secret**. If it leaks, an attacker can sign arbitrary firmware. In a real production system, the private key would be stored in a Hardware Security Module (HSM) — a physically tamper-resistant chip that performs signing operations without ever exposing the key bytes to software.

---

## 7. Ed25519 — The Algorithm We Use

### What is EdDSA?

EdDSA (Edwards-curve Digital Signature Algorithm) is a family of digital signature algorithms. Ed25519 is a specific instance using:
- **Edwards curve:** A special class of elliptic curve with beneficial security properties
- **Curve25519:** A specific curve designed by cryptographer Daniel Bernstein, chosen for efficiency and resistance to side-channel attacks
- **SHA-512:** Used internally within the algorithm for hashing

### What is an elliptic curve?

An elliptic curve is a set of points satisfying an equation like `y² = x³ + ax + b`. The mathematics of adding points on these curves gives us a "one-way trapdoor" function:

- Multiplying a point by a large number (scalar multiplication) is fast
- Given only the result, finding what number was multiplied in is computationally infeasible

The private key is a large random number. The public key is that number multiplied by a fixed starting point on the curve. Reversing this — finding the private key from the public key — is the "Elliptic Curve Discrete Logarithm Problem" (ECDLP), believed to be computationally intractable.

### Why Ed25519 specifically?

| Property | Ed25519 | RSA-2048 | ECDSA P-256 |
|----------|---------|----------|-------------|
| Private key size | 32 B | 256 B | 32 B |
| Public key size | 32 B | 256 B | 64 B |
| Signature size | **64 B** | 256 B | 64 B |
| Verify speed | **~100k/s** | ~10k/s | ~40k/s |
| Constant-time | **Yes** | Needs care | Needs care |
| Secure with weak RNG | **Yes** | No | **No** |
| Side-channel resistant | **Yes** | Needs care | Needs care |

The "constant-time" and "secure with weak RNG" properties are especially critical for embedded systems:

**Constant-time** means the algorithm takes exactly the same number of CPU cycles regardless of the input data. Non-constant-time implementations can leak the private key through timing measurements — an attacker on the same network can send many messages and measure response times to deduce secret values. Ed25519 avoids this entirely.

**Secure with weak RNG** — ECDSA (used in older systems) requires a fresh random number for every signature. If the random number generator has any weakness, the private key can be extracted from just two signatures. Ed25519 does not have this requirement; the randomness is derived deterministically from the private key and message.

---

## 8. The Firmware Image Format

### Why define a custom format?

The bootloader needs to know exactly where to find each piece of information in the firmware file. Rather than using a complex existing format, this project defines a minimal, precisely specified layout.

### The layout

Every signed firmware image has this exact structure:

```
Byte 0x00    Byte 0x04    Byte 0x08    Byte 0x0C                   Byte 0x4C
    │            │            │            │                           │
    ▼            ▼            ▼            ▼                           ▼
┌────────┬────────────┬──────────────┬──────────────────────────┬──────────────── ─ ─
│ MAGIC  │  VERSION   │ PAYLOAD_SIZE │       SIGNATURE          │    PAYLOAD ...
│ 4 bytes│  4 bytes   │   4 bytes    │       64 bytes           │  (PAYLOAD_SIZE bytes)
└────────┴────────────┴──────────────┴──────────────────────────┴──────────────── ─ ─
  "SBOT"   uint32 LE    uint32 LE      Ed25519 over SHA-256        firmware binary
```

Total header size: 4 + 4 + 4 + 64 = **76 bytes (0x4C)**

### Field-by-field explanation

#### MAGIC_WORD (0x00, 4 bytes)

Value: `0x53 0x42 0x4F 0x54` — which is ASCII for the letters S, B, O, T: **"SBOT"** (Secure BOoT).

**Purpose:** Before doing any expensive cryptography, the bootloader checks this first. If the file doesn't start with "SBOT", it is immediately rejected. This is a fast sanity check — it tells the bootloader "this file claims to be a signed OEM image."

**What little-endian means:** Multi-byte numbers can be stored with their bytes in different orders. "Little-endian" stores the least significant byte first. For example, the number 3 stored as a 4-byte little-endian integer is: `03 00 00 00`. This is the convention used by most desktop CPUs (x86) and many embedded CPUs.

#### VERSION (0x04, 4 bytes)

A 32-bit unsigned integer stored in little-endian format. Represents the version number of this firmware image.

This field is the basis for anti-rollback protection. The bootloader compares it against a stored counter.

#### PAYLOAD_SIZE (0x08, 4 bytes)

A 32-bit unsigned integer — the number of bytes of firmware that follow the header. The bootloader uses this to know how many bytes to read as the actual firmware, and importantly, how many bytes to hash before verifying the signature.

**Security check:** The bootloader also verifies that the file is at least `HEADER_SIZE + PAYLOAD_SIZE` bytes long. If not, the image is truncated and must be rejected — this prevents a class of attack where an attacker sends a partial image.

#### SIGNATURE (0x0C, 64 bytes)

The 64-byte Ed25519 signature computed as:

```
signature = ed25519_sign(private_key, SHA-256(payload_bytes))
```

This is the core security field. The bootloader reconstructs `SHA-256(payload)` independently and then uses the manufacturer's public key to verify that this 64-byte value was produced by the matching private key over that exact hash.

#### PAYLOAD (0x4C, variable)

The actual firmware binary — the executable code that the ECU will run after verification. Its length is given by the PAYLOAD_SIZE field.

### Why is the signature over `SHA-256(payload)` and not the header?

The header contains the signature itself. If we included the header in the signed data, we'd have a circular dependency (signing something that contains the signature). By signing only the payload, we avoid this while still binding the signature to the firmware content. The VERSION field, though not directly signed, cannot be forged either — any image with an incorrect VERSION will either fail the anti-rollback check or the attacker would need to re-sign, requiring the private key.

---

## 9. Anti-Rollback

### The time machine problem

Imagine the following timeline:

```
Jan 2024: Firmware v3 shipped. Contains CVE-2024-001 (discovered later).
Mar 2024: Firmware v4 shipped. Patches CVE-2024-001.
Apr 2024: Attacker discovers CVE-2024-001 and wants to exploit it.
          v3 is still correctly signed — the manufacturer signed it.
          Attacker re-flashes v3 to re-expose the vulnerability.
```

A pure signature check would **pass** for v3. The signature is valid. This is why signature verification alone is insufficient — you also need to prevent legitimate-but-outdated images from being installed.

### The monotonic counter

A **monotonic counter** is a number that only ever increases. The device stores the highest version number it has ever accepted.

```
stored_version = 4  (device has accepted v4)

Incoming image VERSION = 3
Check: 3 < 4 → REJECT

Incoming image VERSION = 5
Check: 5 >= 4 → ALLOW (then update stored_version to 5)
```

### Simulation in this project

In real hardware, the monotonic counter is implemented in **eFuses** — tiny physical fuses that can be blown (written) once but never reset. The hardware literally cannot go backwards.

In this simulation, we use a plain text file (`stored_version.txt`) containing one number. This faithfully captures the logic without requiring special hardware.

```
stored_version.txt contents: "4"
```

If the file is absent, the bootloader treats it as version 0 — any firmware version is acceptable. This represents a freshly manufactured device that hasn't established a version baseline yet.

---

## 10. Rust — Why This Language?

### The security problem with C

Most embedded firmware is historically written in C. C is fast and low-level, but it has a fundamental problem: it lets you read and write memory in ways that are incorrect, and the compiler won't stop you.

**Buffer overflow example in C:**
```c
char buffer[10];
// If input is 20 bytes, this writes past the end of the buffer
// into adjacent memory, potentially overwriting other data or code
strcpy(buffer, user_input);
```

Buffer overflows are the most exploited class of vulnerability in history. When parsing binary headers (like our firmware image format), buffer overflows are a primary concern.

### How Rust solves this

Rust's ownership and borrowing system is enforced at **compile time**. The Rust compiler refuses to compile code that could:

- Read past the end of an array
- Use a value after it's been freed from memory
- Have two parts of code modify the same data simultaneously
- Access uninitialised memory

These checks are zero-cost at runtime — once the code compiles, there's no performance overhead.

**The same operation in Rust:**
```rust
let buffer: [u8; 10] = [0u8; 10];
// This is checked at runtime and panics safely
// instead of silently corrupting memory
let byte = buffer[index];  // panics if index >= 10
```

For parsing binary protocols, Rust provides safe slice operations with bounds checking built in. Our bootloader reads the header like this:

```rust
// This is safe: if image_data is too short, we return an error
// before ever reaching this line
let magic = &image_data[0..4];
```

### Memory safety in security-critical contexts

When parsing untrusted binary data (our firmware image came from the network or a USB drive — it might be crafted maliciously), every byte read is a potential attack surface. Rust eliminates an entire category of vulnerabilities from the start.

### `no_std` compatibility

Rust code can be written to work without the standard library (using `#![no_std]`), which means it can run on microcontrollers that have no operating system. Our project uses the standard library for convenience in simulation, but the crypto logic (using `ed25519-dalek` and `sha2`) is fully `no_std` compatible — it could be deployed on bare-metal ECU hardware.

---

## 11. The Two Programs

### Overview

The project is split into two separate programs, reflecting the real-world split of responsibility:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  MANUFACTURER SIDE (secure build server)                                    │
│                                                                             │
│  firmware_signer                                                            │
│  ├── keygen    → generate Ed25519 keypair once, store private key in HSM    │
│  └── sign      → sign each firmware release before distribution             │
└─────────────────────────────────────────────────────────────────────────────┘
                              ↓ signed firmware image ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│  VEHICLE SIDE (ECU, runs on each boot)                                      │
│                                                                             │
│  secure_bootloader                                                          │
│  └── verify → parse header → anti-rollback → SHA-256 → Ed25519 → boot/halt │
└─────────────────────────────────────────────────────────────────────────────┘
```

### firmware_signer — the host tool

**Who runs it:** The manufacturer's build server during the release pipeline.

**Commands:**

```bash
# Generate a keypair (done once)
firmware_signer keygen --secret secret.key --public public.key

# Sign a firmware file
firmware_signer sign \
  --payload firmware.bin \
  --version 5 \
  --key secret.key \
  --output firmware.signed.bin
```

**What `sign` does internally:**
1. Read `firmware.bin` (the raw firmware binary)
2. Compute `SHA-256(firmware.bin)` → 32-byte hash
3. Load private key from `secret.key`
4. Compute `Ed25519.sign(hash, private_key)` → 64-byte signature
5. Construct 76-byte header: MAGIC + VERSION + PAYLOAD_SIZE + SIGNATURE
6. Write header + firmware bytes to `firmware.signed.bin`

### secure_bootloader — the device program

**Who runs it:** The ECU on every power-on.

**Usage:**
```bash
secure_bootloader --image firmware.signed.bin --public-key public.key
```

**What it does internally (in order):**
1. Read the entire image file into memory
2. Check file length ≥ 76 bytes (minimum valid header)
3. Check `MAGIC == "SBOT"` — fail fast if wrong
4. Parse VERSION and PAYLOAD_SIZE from header
5. Check file length ≥ `76 + PAYLOAD_SIZE` — detect truncation
6. Read `stored_version.txt` — compare VERSION ≥ stored
7. Load the 32-byte OEM public key
8. Extract SIGNATURE bytes (64 bytes at offset 0x0C)
9. Extract PAYLOAD bytes (from offset 0x4C, length PAYLOAD_SIZE)
10. Compute `SHA-256(PAYLOAD)` → 32-byte hash
11. Run `Ed25519.verify(signature, hash, public_key)`
12. On success: print `[SUCCESS] Booting image...` and exit 0
13. On any failure: print `[FATAL] <reason>` and exit 1

**Why this exact order matters:** Expensive operations (cryptography) come last. Cheap checks (MAGIC, length, version) fail fast. This is called **defence in depth with early exit** — we don't waste CPU cycles on crypto if the file is obviously malformed.

---

## 12. Walking Through the Code

### The signer — keygen function

```rust
fn keygen(secret_path: &PathBuf, public_path: &PathBuf)
    -> Result<(), Box<dyn std::error::Error>>
{
    // Generate a cryptographically random Ed25519 key pair
    // OsRng = the operating system's random number generator
    // (uses hardware entropy sources like CPU noise or /dev/urandom)
    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);

    // Extract the 32 raw bytes of the secret key
    let secret_bytes: [u8; 32] = signing_key.to_bytes();

    // Derive the public key (mathematically determined from the private key)
    let public_bytes = signing_key.verifying_key().to_bytes();

    // Write both to disk
    fs::write(secret_path, &secret_bytes)?;
    fs::write(public_path, &public_bytes)?;
    Ok(())
}
```

Key points:
- `OsRng` uses hardware entropy — the key cannot be predicted
- The public key is **derived** from the private key, not independently generated
- The `?` operator: if `fs::write` fails (e.g., disk full), the function immediately returns the error

### The signer — sign function

```rust
fn sign(payload_path, version, key_path, output_path) {
    // 1. Read the raw firmware file
    let payload = fs::read(payload_path)?;
    let payload_size = payload.len() as u32;

    // 2. Read the 32-byte private key
    let mut secret_bytes = [0u8; 32];
    fs::File::open(key_path)?.read(&mut secret_bytes)?;
    let signing_key = SigningKey::from_bytes(&secret_bytes);

    // 3. Hash the payload
    let mut hasher = Sha256::new();
    hasher.update(&payload);
    let hash = hasher.finalize();  // 32-byte value

    // 4. Sign the hash
    let signature: Signature = signing_key.sign(&hash);  // 64-byte value

    // 5. Build the 76-byte header
    let mut header = [0u8; HEADER_SIZE];  // 0x4C = 76
    header[0..4].copy_from_slice(&MAGIC);                          // "SBOT"
    header[0x04..0x08].copy_from_slice(&version.to_le_bytes());    // VERSION
    header[0x08..0x0C].copy_from_slice(&payload_size.to_le_bytes());// PAYLOAD_SIZE
    header[0x0C..0x4C].copy_from_slice(signature.as_bytes());      // SIGNATURE

    // 6. Write header + payload
    let mut out = fs::File::create(output_path)?;
    out.write_all(&header)?;
    out.write_all(&payload)?;
}
```

### The bootloader — verification

```rust
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let image_data = fs::read(&cli.image)?;

    // Guard 1: minimum length
    if image_data.len() < HEADER_SIZE {
        return Err("Image file too short".into());
    }

    // Guard 2: magic word check — fast fail
    if &image_data[0..4] != MAGIC {
        return fatal("Invalid magic; not a signed SBOT image.");
    }

    // Parse header fields using little-endian byte decoding
    let version = u32::from_le_bytes([
        image_data[4], image_data[5], image_data[6], image_data[7]
    ]);
    let payload_size = u32::from_le_bytes([
        image_data[8], image_data[9], image_data[10], image_data[11]
    ]) as usize;

    // Guard 3: truncation check
    if image_data.len() < HEADER_SIZE + payload_size {
        return fatal("Image truncated.");
    }

    // Extract raw signature bytes and create Signature struct
    let signature_bytes: [u8; 64] =
        image_data[0x0C..0x4C].try_into().unwrap();
    let signature = Signature::from_bytes(&signature_bytes);

    // Extract payload bytes
    let payload = &image_data[0x4C..0x4C + payload_size];

    // Guard 4: anti-rollback
    let stored_version = read_stored_version("stored_version.txt")?;
    if version < stored_version {
        return fatal("Version downgrade rejected. Halting.");
    }

    // Load public key
    let public_key = VerifyingKey::from_bytes(&key_bytes)?;

    // Recompute SHA-256 of the payload
    let hash = Sha256::digest(payload);

    // Verify Ed25519 signature — this is the cryptographic check
    if public_key.verify(&hash, &signature).is_err() {
        return fatal("Signature mismatch. Halting.");
    }

    println!("[SUCCESS] Booting image...");
    Ok(())
}
```

### What `u32::from_le_bytes` does

`from_le_bytes` reconstructs a 32-bit integer from 4 raw bytes using little-endian interpretation:

```
Bytes in file:  03 00 00 00
                ↑  ↑  ↑  ↑
byte position:  0  1  2  3

Little-endian value = byte[0] + byte[1]*256 + byte[2]*65536 + byte[3]*16777216
                    = 3 + 0 + 0 + 0
                    = 3
```

### What `try_into().unwrap()` does

`try_into()` converts a slice (variable-length) into a fixed-size array (`[u8; 64]`). If the slice is not exactly 64 bytes, it returns an error. `.unwrap()` is safe here because we already verified the file is long enough (the truncation check ensures at least `0x4C` bytes exist and the signature field is exactly at `0x0C..0x4C`).

---

## 13. The Test Suite

Good security code requires adversarial testing — deliberately trying to break it.

### Test 1: Golden Path

**Purpose:** Confirm the normal, legitimate update flow works end-to-end.

```
keygen → secret.key, public.key
sign(firmware.bin, version=1, secret.key) → firmware.signed.bin
bootloader(firmware.signed.bin, public.key, stored_version=0)

Expected: [SUCCESS] Booting image... (exit 0)
```

This test confirms the system doesn't produce false negatives (reject legitimate firmware).

### Test 2: Tamper Test

**Purpose:** Confirm that even a single-bit modification is detected.

```
[same setup as golden path]
flip bit: firmware.signed.bin[0x4C] ^= 1  ← XOR with 1 flips the lowest bit

bootloader(modified_firmware.signed.bin, public.key)

Expected: [FATAL] Signature mismatch. Halting. (exit 1)
```

`^= 1` is the XOR operator. XORing with 1 flips the last bit of a byte: `0b10110100 XOR 0b00000001 = 0b10110101`. This changes the payload by exactly one bit, which completely changes the SHA-256 hash, which makes the signature invalid.

### Test 3: Key Mismatch

**Purpose:** Confirm that a valid signature made with a different key is rejected.

```
keygen A → secret_a.key, public_a.key
keygen B → secret_b.key, public_b.key
sign(firmware.bin, version=1, secret_a.key) → firmware.signed.bin

bootloader(firmware.signed.bin, public_b.key)  ← WRONG KEY

Expected: [FATAL] Signature mismatch. Halting. (exit 1)
```

This simulates an attacker using their own keypair to sign firmware. Their signature is mathematically valid under their key, but completely invalid under the OEM public key burned into the ECU.

### Test 4: Downgrade Attack

**Purpose:** Confirm the anti-rollback mechanism works.

```
sign(firmware.bin, version=1, secret.key) → firmware_v1.signed.bin

echo "2" > stored_version.txt  ← device has already accepted v2

bootloader(firmware_v1.signed.bin, public.key)

Expected: [FATAL] Version downgrade rejected. Halting. (exit 1)
```

Note that the signature *is* valid. The firmware is genuinely signed by the manufacturer. The version check is the only thing that stops this attack.

### Running the tests

```bash
cargo test --workspace
```

Expected output:
```
running 4 tests
test golden_path   ... ok
test tamper        ... ok
test key_mismatch  ... ok
test downgrade     ... ok

test result: ok. 4 passed; 0 failed
```

---

## 14. The Threat Model

A **threat model** is a structured way of thinking about security. It asks: who might attack this system, what can they do, and what can they not do?

### Attacker capabilities (what we assume)

| Capability | Assumed? |
|------------|----------|
| Can intercept OTA network traffic | Yes |
| Can modify firmware files in transit | Yes |
| Can access the OBD-II port with physical vehicle access | Yes |
| Can obtain old, legitimately-signed firmware versions | Yes |
| Knows the structure of our firmware image format | Yes (we treat this as public) |
| Has the manufacturer's private key | **No** (this is the one protected secret) |
| Can modify the bootloader ROM | **No** (physical hardware protection) |
| Can reset the monotonic counter | **No** (hardware fuse simulation) |

### What the system guarantees

Given these assumptions, the system provides:

1. **Authenticity:** Any firmware that passes verification was signed by whoever holds the private key. An attacker without the private key cannot create or modify valid firmware.

2. **Integrity:** Any modification to the payload, no matter how small, is detected. The attacker cannot make an "undetected" change.

3. **Freshness:** The system will not accept firmware older than what it has already accepted. Old vulnerabilities cannot be re-exposed through replay.

### What the system does not guarantee

Being honest about limitations is part of a good threat model:

- **If the private key leaks:** All guarantees break. Key management is outside the scope of this simulation but critical in production.
- **If the bootloader ROM is compromised:** A compromised bootloader could be modified to skip verification. Physical hardware protection (locked JTAG, ROM write protection) is required.
- **If the hardware fuse counter is not implemented:** In this simulation, `stored_version.txt` can be deleted or modified by anyone with file system access. Real anti-rollback requires a hardware counter.
- **Supply chain attacks:** If the firmware is compromised before it reaches the signing step, the signature authenticates malicious code.

---

## 15. How This Maps to the Real World

### Real automotive secure boot (AUTOSAR)

The automotive industry has standardised secure boot through **AUTOSAR** (AUTomotive Open System ARchitecture). The concepts are identical to this project:

- ECUs have immutable bootloader code in protected memory
- Firmware images carry cryptographic signatures
- A Hardware Security Module (HSM) manages keys
- Anti-rollback is enforced by hardware fuses

AUTOSAR SecOC (Secure Onboard Communication) and AUTOSAR Secure Boot are the industry standards.

### HSMs in production

Instead of `secret.key` sitting on a file system, production systems use an **HSM** — a dedicated tamper-resistant chip that:
- Generates and stores keys in hardware that physically destroys them if tampered with
- Performs signing operations without ever exposing key bytes to software
- Enforces policies (e.g., only signs firmware for authorised platforms)
- Maintains an audit log of every signing operation

Examples: Thales Luna, AWS CloudHSM, Nitrokey HSM.

### Real OTA systems

Tesla, over-the-air updates in modern BMWs and Volvos, and virtually all EV manufacturers use cryptographically signed OTA updates. The UNECE WP.29 regulation (UN Regulation No. 155) mandates cybersecurity measures for vehicles sold in the EU, including requirements for software update authentication.

### CVE examples this project defends against

| CVE | Year | Attack | Stopped by |
|-----|------|--------|------------|
| CVE-2015-5611 | 2015 | Remote code execution via CAN bus in Jeep Cherokee | Signature check |
| CVE-2016-9337 | 2016 | Unsigned firmware update in Tesla Model S | Signature check |
| Multiple | 2019 | BMW key fob replay attack | Anti-rollback |

---

## 16. Glossary

| Term | Definition |
|------|-----------|
| **Anti-rollback** | A mechanism that prevents installing older firmware versions |
| **Asymmetric cryptography** | Cryptography using a key pair: one public, one private |
| **Avalanche effect** | Property of hash functions: small input change → large output change |
| **Bootloader** | First code that runs when a computer powers on |
| **Buffer overflow** | Bug where a program writes past the end of allocated memory; major source of security vulnerabilities |
| **Cargo** | Rust's package manager and build system |
| **Constant-time** | Code that takes the same duration regardless of input values, preventing timing side-channel attacks |
| **Crate** | A Rust library or binary package |
| **Curve25519** | An elliptic curve designed by Daniel Bernstein for high security and efficiency |
| **ECU** | Electronic Control Unit — a computer in a vehicle |
| **Ed25519** | A specific digital signature algorithm using Edwards curves |
| **EdDSA** | Edwards-curve Digital Signature Algorithm — the family Ed25519 belongs to |
| **eFuse** | Hardware fuse that can be burned once, used for monotonic counters |
| **Elliptic curve** | A mathematical curve whose point-addition properties enable public-key cryptography |
| **Firmware** | Permanent software stored in hardware chips |
| **Hash function** | A function that maps any input to a fixed-size output deterministically and irreversibly |
| **HSM** | Hardware Security Module — a tamper-resistant device for key storage and cryptographic operations |
| **Little-endian** | Byte order where the least significant byte comes first |
| **Magic number** | A fixed byte sequence at the start of a file that identifies its format |
| **Monotonic counter** | A counter that only increases, never decreases |
| **OBD-II** | On-Board Diagnostics port — present in all cars since 1996, used for diagnostics and sometimes firmware flashing |
| **OEM** | Original Equipment Manufacturer — the car maker |
| **OTA** | Over-The-Air — delivering software updates wirelessly |
| **Payload** | The actual firmware binary, as distinguished from the header metadata |
| **Private key** | The secret half of an asymmetric key pair; used for signing |
| **Public key** | The public half of an asymmetric key pair; used for verification; safe to share |
| **ROM** | Read-Only Memory — cannot be modified after manufacture |
| **Rust** | A systems programming language emphasising memory safety |
| **SHA-256** | Secure Hash Algorithm 256-bit output — a widely used cryptographic hash function |
| **Side-channel attack** | An attack that extracts secret information from physical characteristics (timing, power use) rather than breaking the algorithm directly |
| **Signature** | A value produced by signing data with a private key, verifiable with the matching public key |
| **uint32** | An unsigned 32-bit integer; stores values from 0 to 4,294,967,295 |
| **Workspace** | A Cargo feature grouping multiple related crates under one build configuration |

---

## 17. Further Reading

### Beginner-friendly

- **"Serious Cryptography" by Jean-Philippe Aumasson** — The most readable introduction to modern cryptography for practitioners. Covers hash functions, block ciphers, and public-key cryptography without requiring a mathematics degree.

- **"The Rust Programming Language" (The Book)** — Free online at `doc.rust-lang.org/book`. The official Rust tutorial, very beginner-friendly.

- **"Embedded Rust Book"** — Free at `docs.rust-embedded.org`. Covers running Rust on microcontrollers.

### Standards and specifications

- **UNECE WP.29 / UN R155** — The vehicle cybersecurity regulation that mandates OTA security for vehicles sold in Europe.
- **AUTOSAR Secure Boot** — Industry-standard specification for automotive secure boot.
- **NIST SP 800-131A** — NIST guidance on transitioning to stronger cryptographic algorithms.
- **RFC 8032** — The IETF specification for Ed25519 and Ed448 signature algorithms.

### Go deeper on the algorithms

- **"A Graduate Course in Applied Cryptography"** by Dan Boneh and Victor Shoup — Free at `toc.cryptobook.us`. Covers elliptic curves and Ed25519 in mathematical depth.
- **`ed25519.cr.yp.to`** — Daniel Bernstein's original Ed25519 paper and specification.
- **NIST FIPS 180-4** — The formal specification of SHA-256.

### Automotive security specifically

- **"Car Hacker's Handbook" by Craig Smith** — Practical guide to automotive security research.
- **ISO/SAE 21434** — The international standard for road vehicle cybersecurity engineering.

---

> **Summary:** This project implements a complete chain of trust — from the moment an OEM engineer types `firmware_signer sign`, through transit and storage, to the moment the ECU decides whether to run the code. Every component exists to answer one question with mathematical certainty: *is this firmware genuine, unmodified, and current enough to be trusted?*
