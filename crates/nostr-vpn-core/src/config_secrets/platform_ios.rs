#[cfg(target_os = "ios")]
mod platform {
    use std::path::Path;

    use anyhow::{Context, Result, anyhow};
    use core_foundation::array::CFArray;
    use core_foundation::base::{CFType, TCFType};
    use core_foundation::boolean::CFBoolean;
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;
    use core_foundation_sys::base::{CFGetTypeID, CFRelease, CFTypeRef};
    use core_foundation_sys::string::CFStringRef;
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password,
    };
    use security_framework_sys::base::{errSecDuplicateItem, errSecItemNotFound, errSecSuccess};
    use security_framework_sys::item::{
        kSecAttrAccessGroup, kSecAttrAccount, kSecAttrService, kSecClass, kSecClassGenericPassword,
        kSecMatchLimit, kSecMatchLimitAll, kSecReturnAttributes, kSecReturnData, kSecValueData,
    };
    use security_framework_sys::keychain_item::{
        SecItemAdd, SecItemCopyMatching, SecItemDelete, SecItemUpdate,
    };

    use super::{
        ConfigSecret, SERVICE, hydrate_config_secret_fields, scoped_account_name,
        stable_account_name,
    };

    pub(super) const REDACTED_SECRET_MARKER: &str = "stored-in-ios-keychain";
    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

    pub(super) fn store_name() -> &'static str {
        "the iOS Keychain"
    }

    pub(super) fn allows_plaintext_fallback() -> bool {
        false
    }

    /// Shared access group baked in via NVPN_IOS_KEYCHAIN_ACCESS_GROUP ("<team id>.<bundle id>").
    fn keychain_access_group() -> Option<&'static str> {
        super::normalize_keychain_access_group(option_env!(
            "NVPN_IOS_KEYCHAIN_ACCESS_GROUP"
        ))
    }

    pub(super) fn hydrate_config_secrets(
        path: &Path,
        config: &mut crate::config::AppConfig,
    ) -> Result<()> {
        hydrate_config_secret_fields(path, config)
    }

    pub(super) fn read_secret(path: &Path, kind: ConfigSecret) -> Result<Option<String>> {
        let account = stable_account_name(kind);
        if let Some(value) = read_account(&account, kind)? {
            return Ok(Some(value));
        }

        let legacy_account = scoped_account_name(path, kind);
        if let Some(value) = read_account(&legacy_account, kind)? {
            migrate_legacy_secret(&account, kind, &value);
            return Ok(Some(value));
        }

        recover_legacy_secret(kind)
    }

    pub(super) fn write_secret(_path: &Path, kind: ConfigSecret, value: &str) -> Result<()> {
        let account = stable_account_name(kind);
        write_account(&account, kind, value)
    }

    pub(super) fn delete_secret(path: &Path, kind: ConfigSecret) -> Result<()> {
        let account = stable_account_name(kind);
        delete_account(&account, kind)?;

        let legacy_account = scoped_account_name(path, kind);
        if legacy_account != account {
            delete_account(&legacy_account, kind)?;
        }

        Ok(())
    }

    pub(super) fn recover_nostr_secret_for_public_key(
        expected_public_key: &str,
    ) -> Result<Option<String>> {
        let candidates = legacy_secret_candidates(ConfigSecret::Nostr)?
            .into_iter()
            .map(|(_, value)| value)
            .collect::<Vec<_>>();
        let Some(matching) = super::select_nostr_secret_for_public_key(
            expected_public_key,
            candidates,
        )? else {
            return Ok(None);
        };
        migrate_legacy_secret(
            &stable_account_name(ConfigSecret::Nostr),
            ConfigSecret::Nostr,
            &matching,
        );
        Ok(Some(matching))
    }

    fn read_account(account: &str, kind: ConfigSecret) -> Result<Option<String>> {
        let Some(group) = keychain_access_group() else {
            return read_ungrouped_account(account, kind);
        };
        if let Some(value) = read_grouped_account(account, group, kind)? {
            return Ok(Some(value));
        }
        if let Some(value) = read_ungrouped_account(account, kind)? {
            // Existing installs keep secrets under the default access group;
            // copy them into the shared group on first read.
            if let Err(error) = write_account(account, kind, &value) {
                tracing::warn!(
                    error = ?error,
                    secret = kind.account_suffix(),
                    "failed to adopt an iOS Keychain config secret into the shared access group"
                );
            }
            return Ok(Some(value));
        }
        Ok(None)
    }

    fn read_ungrouped_account(account: &str, kind: ConfigSecret) -> Result<Option<String>> {
        match get_generic_password(SERVICE, account) {
            Ok(bytes) => decode_secret(kind, bytes).map(Some),
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
            Err(error) => Err(anyhow!(error)).with_context(|| {
                format!(
                    "failed to read {} from the iOS Keychain",
                    kind.display_name()
                )
            }),
        }
    }

    fn read_grouped_account(
        account: &str,
        group: &str,
        kind: ConfigSecret,
    ) -> Result<Option<String>> {
        let mut query = grouped_password_query(account, group);
        query.push((
            unsafe { CFString::wrap_under_get_rule(kSecReturnData) },
            CFBoolean::true_value().into_CFType(),
        ));
        let mut ret: CFTypeRef = std::ptr::null();
        let status = unsafe {
            SecItemCopyMatching(
                CFDictionary::from_CFType_pairs(&query).as_concrete_TypeRef(),
                &mut ret,
            )
        };
        if status == errSecItemNotFound {
            return Ok(None);
        }
        keychain_result(status)?;
        if ret.is_null() {
            return Ok(None);
        }
        if unsafe { CFGetTypeID(ret) } != CFData::type_id() {
            unsafe { CFRelease(ret) };
            return Err(anyhow!(
                "the iOS Keychain returned an unexpected type for {}",
                kind.display_name()
            ));
        }
        let data = unsafe { CFData::wrap_under_create_rule(ret.cast()) };
        decode_secret(kind, data.bytes().to_vec()).map(Some)
    }

    fn delete_account(account: &str, kind: ConfigSecret) -> Result<()> {
        match delete_generic_password(SERVICE, account) {
            Ok(()) => Ok(()),
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(()),
            Err(error) => Err(anyhow!(error)).with_context(|| {
                format!(
                    "failed to delete {} from the iOS Keychain",
                    kind.display_name()
                )
            }),
        }?;
        // Also clear any default-group copy written before the shared group existed.
        if let Some(group) = keychain_access_group() {
            let query = grouped_password_query(account, group);
            let status =
                unsafe { SecItemDelete(CFDictionary::from_CFType_pairs(&query).as_concrete_TypeRef()) };
            if status != errSecSuccess && status != errSecItemNotFound {
                return Err(anyhow!(security_framework::base::Error::from_code(status)))
                    .with_context(|| {
                        format!(
                            "failed to delete {} from the iOS Keychain",
                            kind.display_name()
                        )
                    });
            }
        }
        Ok(())
    }

    fn write_account(account: &str, kind: ConfigSecret, value: &str) -> Result<()> {
        let result = match keychain_access_group() {
            Some(group) => set_grouped_password(account, group, value),
            None => set_generic_password(SERVICE, account, value.as_bytes())
                .map_err(anyhow::Error::from),
        };
        result.with_context(|| {
            format!(
                "failed to write {} to the iOS Keychain",
                kind.display_name()
            )
        })
    }

    fn grouped_password_query(account: &str, group: &str) -> Vec<(CFString, CFType)> {
        vec![
            (
                unsafe { CFString::wrap_under_get_rule(kSecClass) },
                unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword) }.into_CFType(),
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecAttrService) },
                CFString::new(SERVICE).into_CFType(),
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) },
                CFString::new(account).into_CFType(),
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecAttrAccessGroup) },
                CFString::new(group).into_CFType(),
            ),
        ]
    }

    fn set_grouped_password(account: &str, group: &str, value: &str) -> Result<()> {
        let mut add_params = grouped_password_query(account, group);
        let value_pair = (
            unsafe { CFString::wrap_under_get_rule(kSecValueData) },
            CFData::from_buffer(value.as_bytes()).into_CFType(),
        );
        add_params.push(value_pair.clone());
        let status = unsafe {
            SecItemAdd(
                CFDictionary::from_CFType_pairs(&add_params).as_concrete_TypeRef(),
                std::ptr::null_mut(),
            )
        };
        if status != errSecDuplicateItem {
            return keychain_result(status);
        }
        let search_params = CFDictionary::from_CFType_pairs(&add_params[..add_params.len() - 1]);
        let update_params = CFDictionary::from_CFType_pairs(std::slice::from_ref(&value_pair));
        let status = unsafe {
            SecItemUpdate(
                search_params.as_concrete_TypeRef(),
                update_params.as_concrete_TypeRef(),
            )
        };
        keychain_result(status)
    }

    fn keychain_result(status: i32) -> Result<()> {
        if status == errSecSuccess {
            return Ok(());
        }
        Err(anyhow!(security_framework::base::Error::from_code(status)))
    }

    fn decode_secret(kind: ConfigSecret, bytes: Vec<u8>) -> Result<String> {
        String::from_utf8(bytes).with_context(|| {
            format!(
                "{} in the iOS Keychain is not valid UTF-8",
                kind.display_name()
            )
        })
    }

    fn recover_legacy_secret(kind: ConfigSecret) -> Result<Option<String>> {
        let candidates = legacy_secret_candidates(kind)?;
        match candidates.as_slice() {
            [] => Ok(None),
            [(account, value)] => {
                let stable_account = stable_account_name(kind);
                migrate_legacy_secret(&stable_account, kind, value);
                tracing::info!(
                    account,
                    secret = kind.account_suffix(),
                    "recovered iOS Keychain config secret from a legacy account"
                );
                Ok(Some(value.clone()))
            }
            _ => Err(anyhow!(
                "{} has multiple legacy iOS Keychain entries; refusing to guess which one to use",
                kind.display_name()
            )),
        }
    }

    fn legacy_secret_candidates(kind: ConfigSecret) -> Result<Vec<(String, String)>> {
        let suffix = format!(":{}", kind.account_suffix());
        let mut candidates = Vec::new();

        for item in query_service_items()? {
            let Some(account) = keychain_string(&item, unsafe { kSecAttrAccount }) else {
                continue;
            };
            if !account.ends_with(&suffix) {
                continue;
            }
            let Some(data) = keychain_data(&item, unsafe { kSecValueData }) else {
                continue;
            };
            let value = String::from_utf8(data).with_context(|| {
                format!(
                    "{} in a legacy iOS Keychain account is not valid UTF-8",
                    kind.display_name()
                )
            })?;
            candidates.push((account, value));
        }

        candidates.sort_by(|left, right| left.0.cmp(&right.0));
        candidates.dedup();
        Ok(candidates)
    }

    fn migrate_legacy_secret(stable_account: &str, kind: ConfigSecret, value: &str) {
        if let Err(error) = write_account(stable_account, kind, value) {
            tracing::warn!(
                error = ?error,
                secret = kind.account_suffix(),
                "failed to migrate legacy iOS Keychain config secret to stable account"
            );
        }
    }

    fn query_service_items() -> Result<Vec<CFDictionary>> {
        let params = vec![
            (
                unsafe { CFString::wrap_under_get_rule(kSecClass) },
                unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword) }.into_CFType(),
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecAttrService) },
                CFString::new(SERVICE).into_CFType(),
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecReturnAttributes) },
                CFBoolean::true_value().into_CFType(),
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecReturnData) },
                CFBoolean::true_value().into_CFType(),
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecMatchLimit) },
                unsafe { CFString::wrap_under_get_rule(kSecMatchLimitAll) }.into_CFType(),
            ),
        ];
        let params = CFDictionary::from_CFType_pairs(&params);
        let mut ret: CFTypeRef = std::ptr::null();
        let status = unsafe { SecItemCopyMatching(params.as_concrete_TypeRef(), &mut ret) };
        if status == errSecItemNotFound {
            return Ok(Vec::new());
        }
        if status != errSecSuccess {
            return Err(anyhow!(security_framework::base::Error::from_code(status)))
                .context("failed to search iOS Keychain config secrets");
        }
        if ret.is_null() {
            return Ok(Vec::new());
        }

        Ok(unsafe { keychain_search_results(ret) })
    }

    unsafe fn keychain_search_results(ret: CFTypeRef) -> Vec<CFDictionary> {
        let type_id = unsafe { CFGetTypeID(ret) };
        if type_id == CFArray::<CFType>::type_id() {
            let array = unsafe { CFArray::<CFType>::wrap_under_create_rule(ret.cast()) };
            return array
                .iter()
                .filter_map(|item| {
                    if unsafe { CFGetTypeID(item.as_CFTypeRef()) }
                        == CFDictionary::<*const std::ffi::c_void, *const std::ffi::c_void>::type_id()
                    {
                        Some(unsafe {
                            CFDictionary::wrap_under_get_rule(item.as_CFTypeRef().cast())
                        })
                    } else {
                        None
                    }
                })
                .collect();
        }

        if type_id == CFDictionary::<*const std::ffi::c_void, *const std::ffi::c_void>::type_id() {
            return vec![unsafe { CFDictionary::wrap_under_create_rule(ret.cast()) }];
        }

        unsafe { CFRelease(ret) };
        Vec::new()
    }

    fn keychain_string(item: &CFDictionary, key: CFStringRef) -> Option<String> {
        let key_name = unsafe { CFString::wrap_under_get_rule(key) }.to_string();
        let (keys, values) = item.get_keys_and_values();
        for (candidate_key, value) in keys.iter().zip(values.iter()) {
            let candidate_name =
                unsafe { CFString::wrap_under_get_rule((*candidate_key).cast()) }.to_string();
            if candidate_name != key_name {
                continue;
            }
            if unsafe { CFGetTypeID(*value) } == CFString::type_id() {
                return Some(unsafe { CFString::wrap_under_get_rule((*value).cast()) }.to_string());
            }
        }
        None
    }

    fn keychain_data(item: &CFDictionary, key: CFStringRef) -> Option<Vec<u8>> {
        let key_name = unsafe { CFString::wrap_under_get_rule(key) }.to_string();
        let (keys, values) = item.get_keys_and_values();
        for (candidate_key, value) in keys.iter().zip(values.iter()) {
            let candidate_name =
                unsafe { CFString::wrap_under_get_rule((*candidate_key).cast()) }.to_string();
            if candidate_name != key_name {
                continue;
            }
            if unsafe { CFGetTypeID(*value) } == CFData::type_id() {
                let data = unsafe { CFData::wrap_under_get_rule((*value).cast()) };
                return Some(data.bytes().to_vec());
            }
        }
        None
    }
}
