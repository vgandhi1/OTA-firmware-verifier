//! Secure bootloader: reads a signed firmware image, verifies Ed25519 signature over
//! SHA-256(payload), enforces anti-rollback via stored_version.txt, then reports success or halt.
//! Header format: MAGIC(4) | VERSION(4) | PAYLOAD_SIZE(4) | SIGNATURE(64) | PAYLOAD (see architecture.md).

use clap::Parser;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

/// MAGIC_WORD: "SBOT" at 0x00
const MAGIC: [u8; 4] = [0x53, 0x42, 0x4F, 0x54];

const HEADER_SIZE: usize = 0x4C;
const SIGNATURE_OFFSET: usize = 0x0C;
const SIGNATURE_LEN: usize = 64;

/// Default path for the monotonic version counter (simulated hardware fuse).
const STORED_VERSION_FILE: &str = "stored_version.txt";

#[derive(Parser)]
#[command(name = "secure_bootloader")]
#[command(about = "Verify signed firmware image and boot or halt")]
struct Cli {
    /// Path to the signed firmware image
    #[arg(short, long, default_value = "firmware.signed.bin")]
    image: PathBuf,

    /// Path to OEM public key (32 bytes). If omitted, uses hardcoded key from build.
    #[arg(short, long)]
    public_key: Option<PathBuf>,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let image_data = fs::read(&cli.image)?;

    if image_data.len() < HEADER_SIZE {
        return Err("Image file too short: missing header".into());
    }

    let magic = &image_data[0..4];
    if magic != MAGIC {
        return fatal("Invalid magic; not a signed SBOT image.");
    }

    let version = u32::from_le_bytes([image_data[4], image_data[5], image_data[6], image_data[7]]);
    let payload_size = u32::from_le_bytes([
        image_data[8],
        image_data[9],
        image_data[10],
        image_data[11],
    ]) as usize;

    if image_data.len() < HEADER_SIZE + payload_size {
        return fatal("Image truncated: payload size exceeds file length.");
    }

    let signature_bytes: [u8; SIGNATURE_LEN] = image_data[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_LEN]
        .try_into()
        .unwrap();
    let signature = Signature::from_bytes(&signature_bytes);
    let payload = &image_data[HEADER_SIZE..HEADER_SIZE + payload_size];

    // Anti-rollback: reject if image version < stored version
    let stored_version = read_stored_version(STORED_VERSION_FILE)?;
    if version < stored_version {
        return fatal("Version downgrade rejected. Halting.");
    }

    // Load public key: from file or hardcoded (simulating ROM)
    let public_key = if let Some(path) = &cli.public_key {
        let bytes: [u8; 32] = fs::read(path)?
            .try_into()
            .map_err(|_| "public key file must be exactly 32 bytes")?;
        VerifyingKey::from_bytes(&bytes).map_err(|_| "Invalid public key bytes")?
    } else {
        VerifyingKey::from_bytes(&HARDCODED_PUBLIC_KEY).map_err(|_| {
            "Invalid hardcoded public key; use --public-key to supply the OEM key."
        })?
    };

    // Verify: signature is over SHA-256(payload)
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let hash = hasher.finalize();

    if public_key.verify(&hash, &signature).is_err() {
        return fatal("Signature mismatch. Halting.");
    }

    println!("[SUCCESS] Booting image...");
    Ok(())
}

/// Placeholder OEM public key (32 bytes). In production this would be burned in at build time.
/// Use --public-key to supply the key that matches the signer's keypair.
const HARDCODED_PUBLIC_KEY: [u8; 32] = [0u8; 32];

fn read_stored_version(path: &str) -> Result<u32, Box<dyn std::error::Error>> {
    let s = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e.into()),
    };
    let s = s.trim();
    Ok(s.parse::<u32>().unwrap_or(0))
}

fn fatal(msg: &str) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("[FATAL] {}", msg);
    std::process::exit(1);
}
