fn main() {
    // NVPN_IOS_KEYCHAIN_ACCESS_GROUP is read with option_env! by the iOS
    // keychain code, so a changed value must force a rebuild.
    println!("cargo:rerun-if-env-changed=NVPN_IOS_KEYCHAIN_ACCESS_GROUP");
}
