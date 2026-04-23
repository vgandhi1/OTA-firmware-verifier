# Project Plan: Embedded Secure Boot & OTA Update Verifier

**Target Role:** Security Manufacturing Engineer
**Focus:** Rust, Embedded Systems Security, Digital Signatures, Firmware Integrity.
**Status:** 🟡 Planned

---

## 1. Executive Summary
**Objective:**
Develop a simulated bootloader in Rust that cryptographically verifies the integrity and authenticity of an Over-The-Air (OTA) firmware image before allowing it to execute.

**Business Value:**
Prevents attackers from loading compromised, malicious, or downgraded firmware onto a vehicle ECU via physical diagnostic ports or remote updates. This directly answers the JD requirement to "design and implement security features that enable scalable development practices" and "familiarity with embedded systems."

---

## 2. Implementation Phases



### Phase 1: The "Signer" Tool (Host/CI Side)
**Goal:** Build a DevSecOps utility for the build server to sign official firmware releases.
- [ ] **Task 1.1:** Create a Rust CLI tool (`firmware_signer`).
- [ ] **Task 1.2:** Implement Ed25519 key generation (one Public Key, one Private Key).
- [ ] **Task 1.3:** Write logic to take a dummy `.bin` file, hash it (SHA-256), sign the hash with the Private Key, and append the signature to a custom firmware header.

### Phase 2: The "Bootloader" Verifier (Device Side)
**Goal:** Build the Rust program that runs on the device to verify the image.
- [ ] **Task 2.1:** Initialize a new Rust project (`cargo new secure_bootloader`).
- [ ] **Task 2.2:** Hardcode the Ed25519 Public Key into the Rust source code (simulating a burned-in key in hardware/ROM).
- [ ] **Task 2.3:** Write logic to read the signed `.bin` file from disk.
- [ ] **Task 2.4:** Implement a parser to separate the custom header (containing the signature and version) from the actual executable payload.

### Phase 3: Cryptographic Verification Logic
**Goal:** The core security check.
- [ ] **Task 3.1:** Integrate a Rust crypto crate (e.g., `ed25519-dalek` and `sha2`).
- [ ] **Task 3.2:** Hash the payload extracted in Phase 2.
- [ ] **Task 3.3:** Verify the payload's hash against the header's signature using the hardcoded Public Key.
- [ ] **Task 3.4:** Print `[SUCCESS] Booting image...` or `[FATAL] Signature mismatch. Halting.`

### Phase 4: Anti-Rollback Protection 
**Goal:** Prevent attackers from flashing an older, vulnerable version of official firmware.
- [ ] **Task 4.1:** Add a `Version` integer to the custom firmware header in the Signer tool.
- [ ] **Task 4.2:** Update the Bootloader to read a local `stored_version.txt` file (simulating a monotonic counter in hardware).
- [ ] **Task 4.3:** Reject the firmware if the new header version is strictly less than the stored version.

---

## 3. Testing Strategy
* **Golden Path:** Sign a valid binary, pass it to the bootloader, assert successful verification.
* **Tamper Test:** Sign a valid binary, flip one bit in the payload using a hex editor, assert the bootloader rejects it.
* **Key Mismatch:** Sign a binary with "Keypair A", attempt to verify with a bootloader holding "Public Key B", assert rejection.
* **Downgrade Attack Test:** Attempt to load a validly signed firmware with Version 1 when the Bootloader's monotonic counter is at Version 2. Assert rejection.