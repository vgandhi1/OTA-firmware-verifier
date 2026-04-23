# Architecture: Embedded Secure Boot & OTA Verifier

## 1. High-Level Design
The Secure Boot process ensures that the vehicle's processor will only execute firmware code that has been cryptographically signed by the Original Equipment Manufacturer (OEM).



* **Power On:** The Bootloader executes from Read-Only Memory (ROM).
* **Read Header:** The Bootloader reads the firmware header from Flash memory.
* **Verify Signature:** The signature in the header is verified using the OEM Public Key hardcoded into the bootloader.
* **Execution/Halt:** If valid, the program counter jumps to the firmware payload. If invalid, the device halts or falls back to a recovery partition.

---

## 2. Firmware Image Format
To package the firmware with its required security metadata, we define a custom binary image format. The Bootloader parses this exact structure byte-by-byte.

| Byte Offset | Field Name | Data Type | Description |
| :--- | :--- | :--- | :--- |
| **0x00** | `MAGIC_WORD` | `uint32` | `0x53 0x42 0x4F 0x54` ("SBOT") to identify image. |
| **0x04** | `VERSION` | `uint32` | Monotonically increasing version number. |
| **0x08** | `PAYLOAD_SIZE`| `uint32` | Size of the executable code in bytes. |
| **0x0C** | `SIGNATURE` | `bytes(64)` | Ed25519 Digital Signature of the payload. |
| **0x4C** | `PAYLOAD` | `bytes` | The actual executable firmware binary. |

---

## 3. Cryptographic Implementation Details
* **Algorithm:** Ed25519 (EdDSA over Curve25519). Chosen for its high performance, small signature size (64 bytes), and strong resistance to side-channel attacks.
* **Hashing:** SHA-256 is used to hash the payload before signature verification.
* **Language/Libraries:** Implemented in Rust to guarantee memory safety (preventing buffer overflows during header parsing). Uses the `ed25519-dalek` and `sha2` crates.

---

## 4. Threat Model & Mitigations

| Threat | Description | Mitigation Strategy |
| :--- | :--- | :--- |
| **Malicious USB Flash** | Attacker attempts to load custom firmware via a diagnostic port. | Bootloader rejects the image because the attacker lacks the OEM's private key to generate a valid signature. |
| **OTA Tampering** | Firmware is corrupted or altered over the air network. | Modifying a single byte changes the SHA-256 hash, causing the Ed25519 signature verification to fail immediately. |
| **Version Downgrade** | Attacker flashes an older, officially signed firmware containing known vulnerabilities. | Bootloader enforces Anti-Rollback by checking the `VERSION` header against a stored monotonic counter, rejecting older versions. |