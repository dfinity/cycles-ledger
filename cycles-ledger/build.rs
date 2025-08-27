use std::env;
use std::fs;
use std::path::Path;

struct IndexWasm {
    url: &'static str,
    expected_sha256: &'static str,
    target_filename: &'static str,
    env_var_prefix: &'static str,
}

const MAINNET_INDEX_WASM: IndexWasm = IndexWasm {
    url: "https://github.com/dfinity/ic/releases/download/ledger-suite-icrc-2024-11-28/ic-icrc1-index-ng-u256.wasm.gz",
    expected_sha256: "d615ea66e7ec7e39a3912889ffabfabb9b6f200584b9656789c3578fae1afac7",
    target_filename: "mainnet-ic-icrc1-index-ng-u256.wasm.gz",
    env_var_prefix: "MAINNET",
};
const LATEST_INDEX_WASM: IndexWasm = IndexWasm {
    url: "https://github.com/dfinity/ic/releases/download/ledger-suite-icrc-2025-06-19/ic-icrc1-index-ng-u256.wasm.gz",
    expected_sha256: "6c406b9dc332f3dc58b823518ab2b2c481467307ad9e540122f17bd9b926c123",
    target_filename: "latest-ic-icrc1-index-ng-u256.wasm.gz",
    env_var_prefix: "LATEST",
};

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();

    for wasm in &[MAINNET_INDEX_WASM, LATEST_INDEX_WASM] {
        let target_path = Path::new(&out_dir).join(wasm.target_filename);

        if target_path.exists() && verify_sha256(&target_path, wasm.expected_sha256).is_err() {
            fs::remove_file(&target_path).expect("Failed to remove outdated WASM file");
        }
        if !target_path.exists() {
            download_index_wasm(wasm, &target_path);
        }

        // Tell Cargo to set an environment variable for tests
        println!(
            "cargo:rustc-env={}_INDEX_WASM_PATH={}",
            wasm.env_var_prefix,
            target_path.display()
        );
    }

    // Rerun if the build script changes
    println!("cargo:rerun-if-changed=build.rs");
}

fn download_index_wasm(index_wasm: &IndexWasm, target_path: &Path) {
    let url = index_wasm.url;
    let expected_sha256 = index_wasm.expected_sha256;

    println!("cargo:info=Downloading WASM file from {}", url);

    // Download the file
    let response = ureq::get(url).call().expect("Failed to download WASM file");

    let mut file = fs::File::create(target_path).expect("Failed to create target file");

    std::io::copy(&mut response.into_reader(), &mut file)
        .expect("Failed to write downloaded content");

    // Verify SHA256
    if let Err(err) = verify_sha256(target_path, expected_sha256) {
        panic!("{}", err);
    }
}

fn verify_sha256(file_path: &Path, expected: &str) -> Result<(), String> {
    use sha2::{Digest, Sha256};

    let content = fs::read(file_path).expect("Failed to read downloaded file");
    let mut hasher = Sha256::new();
    hasher.update(&content);
    let result = format!("{:x}", hasher.finalize());

    if result == expected {
        Ok(())
    } else {
        Err(format!(
            "SHA256 mismatch! Expected: {}, Got: {}",
            expected, result
        ))
    }
}
