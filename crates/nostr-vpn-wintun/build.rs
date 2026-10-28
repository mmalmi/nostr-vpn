use sha2::{Digest, Sha256};
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::PathBuf;

// The exact dependency in Cargo.toml and Cargo.lock must match this package.
// DLL hashes were derived from the crates.io archive after verifying its locked
// SHA-256: da99be64b5aa3de869c16977994314d0759a698d9a73ab0a5b1d52e2282033ae.
const WINTUN_PACKAGE: &str = "wintun-0.5.1";

fn main() {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    println!("cargo:rerun-if-env-changed=CARGO_HOME");
    println!("cargo:rerun-if-env-changed=HOME");
    println!("cargo:rerun-if-env-changed=USERPROFILE");
    let bytes = verified_wintun_dll().unwrap_or_else(|error| panic!("{error}"));

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let profile = env::var("PROFILE").expect("PROFILE");
    let target_dir = out_dir
        .ancestors()
        .find(|path| path.file_name() == Some(OsStr::new(&profile)))
        .expect("failed to derive target profile dir from OUT_DIR");
    let target_dll = target_dir.join("wintun.dll");
    if fs::read(&target_dll).ok().as_deref() != Some(bytes.as_slice()) {
        // Copy the verified bytes, without reopening a mutable cache input.
        fs::write(&target_dll, bytes)
            .unwrap_or_else(|error| panic!("failed to write {}: {error}", target_dll.display()));
    }
    println!("cargo:rerun-if-changed={}", target_dll.display());
    println!(
        "cargo:rustc-env=NOSTR_VPN_WINTUN_DLL_SOURCE={}",
        target_dll.display()
    );
}

fn verified_wintun_dll() -> Result<Vec<u8>, String> {
    let (arch_dir, expected_hash) = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86") => (
            "x86",
            "d694fa46ab4cfebcb2632d094c7aa97278eef2f8052438621766d863ae98a931",
        ),
        Ok("x86_64") => (
            "amd64",
            "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce",
        ),
        Ok("arm") => (
            "arm",
            "daad267411ecdc70a0535e274d2c3e9da3d0084bdac7662cb8424dd4a031b4d9",
        ),
        Ok("aarch64") => (
            "arm64",
            "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80",
        ),
        Ok(other) => return Err(format!("unsupported windows arch {other}")),
        Err(error) => return Err(error.to_string()),
    };

    let cargo_home = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(default_cargo_home)
        .ok_or_else(|| "unable to resolve cargo home".to_string())?;
    let registry_src = cargo_home.join("registry").join("src");
    let mut registries = fs::read_dir(&registry_src)
        .map_err(|error| format!("failed to read {}: {error}", registry_src.display()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    registries.sort();

    let mut verified = None;
    for registry in registries.into_iter().filter(|path| path.is_dir()) {
        let package = registry.join(WINTUN_PACKAGE);
        if !package.exists() {
            continue;
        }
        let candidate = package
            .join("wintun")
            .join("bin")
            .join(arch_dir)
            .join("wintun.dll");
        println!("cargo:rerun-if-changed={}", candidate.display());
        let bytes = fs::read(&candidate)
            .map_err(|error| format!("failed to read pinned {}: {error}", candidate.display()))?;
        let actual_hash = format!("{:x}", Sha256::digest(&bytes));
        if actual_hash != expected_hash {
            return Err(format!(
                "wintun.dll SHA-256 mismatch at {}: expected {expected_hash}, got {actual_hash}",
                candidate.display()
            ));
        }
        // Identical verified copies in multiple registry caches are harmless.
        // Every matching package must verify; a stale second copy is an error.
        verified = Some(bytes);
    }
    verified.ok_or_else(|| {
        format!(
            "pinned {WINTUN_PACKAGE}/wintun/bin/{arch_dir}/wintun.dll not found under {}",
            registry_src.display()
        )
    })
}

fn default_cargo_home() -> Option<PathBuf> {
    env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("USERPROFILE").map(PathBuf::from))
        .map(|home| home.join(".cargo"))
}
