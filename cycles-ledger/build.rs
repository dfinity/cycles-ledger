use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let target_path = Path::new(&out_dir).join("ic-icrc1-index-ng-u256.wasm.gz");

    // Only download if file doesn't exist
    if !target_path.exists() {
        download_wasm_file(&target_path);
    }

    // Tell Cargo to set an environment variable for tests
    println!("cargo:rustc-env=INDEX_WASM_PATH={}", target_path.display());

    // Rerun if the build script changes
    println!("cargo:rerun-if-changed=build.rs");
}

fn download_wasm_file(target_path: &Path) {
    let url = "https://github.com/dfinity/ic/releases/download/ledger-suite-icrc-2025-06-19/ic-icrc1-index-ng-u256.wasm.gz";
    let expected_sha256 = "6c406b9dc332f3dc58b823518ab2b2c481467307ad9e540122f17bd9b926c123";

    println!("cargo:info=Downloading WASM file from {}", url);

    // Download the file
    let response = ureq::get(url).call().expect("Failed to download WASM file");

    let mut file = fs::File::create(target_path).expect("Failed to create target file");

    std::io::copy(&mut response.into_reader(), &mut file)
        .expect("Failed to write downloaded content");

    // Verify SHA256
    verify_sha256(target_path, expected_sha256);
}

fn verify_sha256(file_path: &Path, expected: &str) {
    use sha2::{Digest, Sha256};

    let content = fs::read(file_path).expect("Failed to read downloaded file");
    let mut hasher = Sha256::new();
    hasher.update(&content);
    let result = format!("{:x}", hasher.finalize());

    if result != expected {
        panic!("SHA256 mismatch! Expected: {}, Got: {}", expected, result);
    }
}
