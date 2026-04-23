//! Integration tests: golden path, tamper, key mismatch, downgrade.
//! Runs firmware_signer and secure_bootloader via `cargo run -p` from workspace root.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn workspace_root() -> PathBuf {
    PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("..")
}

fn run_signer(args: &[&str], cwd: &PathBuf) -> std::process::Output {
    let mut cmd = Command::new("cargo");
    cmd.args(["run", "-p", "firmware_signer", "--"])
        .args(args)
        .current_dir(cwd)
        .env_remove("CARGO_TARGET_DIR");
    cmd.output().expect("failed to run firmware_signer")
}

fn run_bootloader(args: &[&str], cwd: &PathBuf) -> std::process::Output {
    let mut cmd = Command::new("cargo");
    cmd.args(["run", "-p", "secure_bootloader", "--"])
        .args(args)
        .current_dir(cwd)
        .env_remove("CARGO_TARGET_DIR");
    cmd.output().expect("failed to run secure_bootloader")
}

#[test]
fn golden_path() {
    let root = workspace_root();
    let test_dir = root.join("target").join("integration_tests").join("golden_path");
    let _ = fs::create_dir_all(&test_dir);
    let payload_path = test_dir.join("firmware.bin");
    let secret_path = test_dir.join("secret.key");
    let public_path = test_dir.join("public.key");
    let signed_path = test_dir.join("firmware.signed.bin");

    // Create a small dummy payload
    fs::write(&payload_path, b"dummy firmware payload for golden path test").unwrap();

    // Keygen
    let out = run_signer(
        &[
            "keygen",
            "--secret",
            secret_path.to_str().unwrap(),
            "--public",
            public_path.to_str().unwrap(),
        ],
        &root,
    );
    assert!(out.status.success(), "keygen failed: {}", String::from_utf8_lossy(&out.stderr));

    // Sign
    let out = run_signer(
        &[
            "sign",
            "--payload",
            payload_path.to_str().unwrap(),
            "--version",
            "1",
            "--key",
            secret_path.to_str().unwrap(),
            "--output",
            signed_path.to_str().unwrap(),
        ],
        &root,
    );
    assert!(out.status.success(), "sign failed: {}", String::from_utf8_lossy(&out.stderr));

    // Bootloader verify (no stored_version.txt => 0, so version 1 is allowed)
    let out = run_bootloader(
        &[
            "--image",
            signed_path.to_str().unwrap(),
            "--public-key",
            public_path.to_str().unwrap(),
        ],
        &test_dir,
    );
    assert!(
        out.status.success(),
        "bootloader should succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("[SUCCESS]"),
        "expected [SUCCESS] in output: {}",
        stdout
    );
}

#[test]
fn tamper() {
    let root = workspace_root();
    let test_dir = root.join("target").join("integration_tests").join("tamper");
    let _ = fs::create_dir_all(&test_dir);
    let payload_path = test_dir.join("firmware.bin");
    let secret_path = test_dir.join("secret.key");
    let public_path = test_dir.join("public.key");
    let signed_path = test_dir.join("firmware.signed.bin");

    fs::write(&payload_path, b"dummy payload").unwrap();

    let out = run_signer(
        &[
            "keygen",
            "--secret",
            secret_path.to_str().unwrap(),
            "--public",
            public_path.to_str().unwrap(),
        ],
        &root,
    );
    assert!(out.status.success());

    let out = run_signer(
        &[
            "sign",
            "--payload",
            payload_path.to_str().unwrap(),
            "--version",
            "1",
            "--key",
            secret_path.to_str().unwrap(),
            "--output",
            signed_path.to_str().unwrap(),
        ],
        &root,
    );
    assert!(out.status.success());

    // Flip one bit in the payload (first byte of payload is at offset 0x4C)
    let mut data = fs::read(&signed_path).unwrap();
    let payload_start = 0x4C;
    if data.len() > payload_start {
        data[payload_start] ^= 1;
        fs::write(&signed_path, &data).unwrap();
    }

    let out = run_bootloader(
        &[
            "--image",
            signed_path.to_str().unwrap(),
            "--public-key",
            public_path.to_str().unwrap(),
        ],
        &test_dir,
    );
    assert!(
        !out.status.success(),
        "bootloader must reject tampered image"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("FATAL") || stderr.contains("Signature mismatch"),
        "expected FATAL or Signature mismatch: {}",
        stderr
    );
}

#[test]
fn key_mismatch() {
    let root = workspace_root();
    let test_dir = root.join("target").join("integration_tests").join("key_mismatch");
    let _ = fs::create_dir_all(&test_dir);
    let payload_path = test_dir.join("firmware.bin");
    let secret_a = test_dir.join("secret_a.key");
    let public_a = test_dir.join("public_a.key");
    let public_b = test_dir.join("public_b.key");
    let signed_path = test_dir.join("firmware.signed.bin");

    fs::write(&payload_path, b"payload").unwrap();

    // Keypair A
    let out = run_signer(
        &[
            "keygen",
            "--secret",
            secret_a.to_str().unwrap(),
            "--public",
            public_a.to_str().unwrap(),
        ],
        &root,
    );
    assert!(out.status.success());

    // Keypair B (we only need public B for bootloader)
    let out = run_signer(
        &[
            "keygen",
            "--secret",
            test_dir.join("secret_b.key").to_str().unwrap(),
            "--public",
            public_b.to_str().unwrap(),
        ],
        &root,
    );
    assert!(out.status.success());

    // Sign with A
    let out = run_signer(
        &[
            "sign",
            "--payload",
            payload_path.to_str().unwrap(),
            "--version",
            "1",
            "--key",
            secret_a.to_str().unwrap(),
            "--output",
            signed_path.to_str().unwrap(),
        ],
        &root,
    );
    assert!(out.status.success());

    // Verify with B's public key => must fail
    let out = run_bootloader(
        &[
            "--image",
            signed_path.to_str().unwrap(),
            "--public-key",
            public_b.to_str().unwrap(),
        ],
        &test_dir,
    );
    assert!(!out.status.success(), "bootloader must reject wrong key");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("FATAL") || stderr.contains("Signature mismatch"),
        "expected FATAL or Signature mismatch: {}",
        stderr
    );
}

#[test]
fn downgrade() {
    let root = workspace_root();
    let test_dir = root.join("target").join("integration_tests").join("downgrade");
    let _ = fs::create_dir_all(&test_dir);
    let payload_path = test_dir.join("firmware.bin");
    let secret_path = test_dir.join("secret.key");
    let public_path = test_dir.join("public.key");
    let signed_v1_path = test_dir.join("firmware_v1.signed.bin");
    let stored_version_path = test_dir.join("stored_version.txt");

    fs::write(&payload_path, b"firmware").unwrap();

    let out = run_signer(
        &[
            "keygen",
            "--secret",
            secret_path.to_str().unwrap(),
            "--public",
            public_path.to_str().unwrap(),
        ],
        &root,
    );
    assert!(out.status.success());

    // Sign version 1
    let out = run_signer(
        &[
            "sign",
            "--payload",
            payload_path.to_str().unwrap(),
            "--version",
            "1",
            "--key",
            secret_path.to_str().unwrap(),
            "--output",
            signed_v1_path.to_str().unwrap(),
        ],
        &root,
    );
    assert!(out.status.success());

    // Simulate device that has already seen version 2
    fs::write(&stored_version_path, "2").unwrap();

    // Try to boot version 1 => must reject
    let out = run_bootloader(
        &[
            "--image",
            signed_v1_path.to_str().unwrap(),
            "--public-key",
            public_path.to_str().unwrap(),
        ],
        &test_dir,
    );
    assert!(!out.status.success(), "bootloader must reject version downgrade");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("downgrade") || stderr.contains("FATAL"),
        "expected downgrade rejection: {}",
        stderr
    );
}
