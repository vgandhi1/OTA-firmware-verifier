//! Firmware signer: CLI to generate Ed25519 keys and sign firmware images
//! per the OTA Verifier architecture (header: MAGIC, VERSION, PAYLOAD_SIZE, SIGNATURE; then payload).
//! Signs SHA-256(payload) with Ed25519; all multi-byte header fields are little-endian.

use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

/// MAGIC_WORD: "SBOT" at 0x00
const MAGIC: [u8; 4] = [0x53, 0x42, 0x4F, 0x54];

/// Header layout: 0x00 MAGIC(4) | 0x04 VERSION(4) | 0x08 PAYLOAD_SIZE(4) | 0x0C SIGNATURE(64) | 0x4C PAYLOAD
const HEADER_SIZE: usize = 0x4C;
const SIGNATURE_OFFSET: usize = 0x0C;
const SIGNATURE_LEN: usize = 64;

#[derive(Parser)]
#[command(name = "firmware_signer")]
#[command(about = "Sign firmware images for secure boot")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate Ed25519 keypair; writes secret key and public key to files.
    Keygen {
        /// Path to write the secret key (32 bytes)
        #[arg(short, long, default_value = "secret.key")]
        secret: PathBuf,
        /// Path to write the public key (32 bytes), for burning into bootloader
        #[arg(short, long, default_value = "public.key")]
        public: PathBuf,
    },
    /// Sign a raw firmware .bin file and emit a signed image.
    Sign {
        /// Path to the raw firmware payload (.bin)
        #[arg(short, long)]
        payload: PathBuf,
        /// Version number (monotonic) for anti-rollback
        #[arg(short, long)]
        version: u32,
        /// Path to the secret key file (from keygen)
        #[arg(short, long)]
        key: PathBuf,
        /// Path for the signed output image
        #[arg(short, long)]
        output: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Keygen { secret, public } => keygen(&secret, &public),
        Commands::Sign {
            payload,
            version,
            key,
            output,
        } => sign(&payload, version, &key, &output),
    }
}

fn keygen(secret_path: &PathBuf, public_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let secret_bytes: [u8; 32] = signing_key.to_bytes();
    let public_bytes = signing_key.verifying_key().to_bytes();

    fs::write(secret_path, &secret_bytes)?;
    fs::write(public_path, &public_bytes)?;

    println!("Wrote secret key to {}", secret_path.display());
    println!("Wrote public key to {}", public_path.display());
    Ok(())
}

fn sign(
    payload_path: &PathBuf,
    version: u32,
    key_path: &PathBuf,
    output_path: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = fs::read(payload_path)?;
    let payload_size = payload.len() as u32;

    let mut secret_bytes = [0u8; 32];
    let n = fs::File::open(key_path)?.read(&mut secret_bytes)?;
    if n != 32 {
        return Err("secret key file must be exactly 32 bytes".into());
    }
    let signing_key = SigningKey::from_bytes(&secret_bytes);

    // Sign SHA-256(payload) for consistency with bootloader verification
    let mut hasher = Sha256::new();
    hasher.update(&payload);
    let hash = hasher.finalize();
    let signature: Signature = signing_key.sign(&hash);

    let mut header = [0u8; HEADER_SIZE];
    header[0..4].copy_from_slice(&MAGIC);
    header[0x04..0x08].copy_from_slice(&version.to_le_bytes());
    header[0x08..0x0C].copy_from_slice(&payload_size.to_le_bytes());
    header[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_LEN].copy_from_slice(&signature.to_bytes());

    let mut out = fs::File::create(output_path)?;
    out.write_all(&header)?;
    out.write_all(&payload)?;
    out.sync_all()?;

    println!("Signed image written to {}", output_path.display());
    Ok(())
}
