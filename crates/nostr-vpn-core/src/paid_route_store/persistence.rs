use super::*;
use std::fs::OpenOptions;

#[cfg(unix)]
use std::fs::File;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

pub fn paid_route_store_file_path(config_path: &Path) -> PathBuf {
    let parent = config_path
        .parent()
        .map_or_else(|| Path::new(".").to_path_buf(), PathBuf::from);
    parent.join("paid-routes.json")
}

pub fn paid_route_payment_outbox_directory(config_path: &Path) -> PathBuf {
    paid_route_store_file_path(config_path)
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("paid-exit-payment-outbox")
}

pub fn paid_route_payment_id(envelope: &StreamingRoutePaymentEnvelope) -> Result<String> {
    use sha2::{Digest, Sha256};

    let encoded =
        serde_json::to_vec(envelope).context("failed to encode paid route payment envelope")?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

pub fn load_paid_route_store(path: &Path) -> Result<PaidRouteStore> {
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(PaidRouteStore::default()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read paid route store {}", path.display()));
        }
    };

    let mut value = match serde_json::from_str::<serde_json::Value>(&raw) {
        Ok(value) => value,
        Err(error) => {
            eprintln!(
                "discarding unreadable paid route store {}: {error}",
                path.display()
            );
            return Ok(PaidRouteStore::default());
        }
    };
    let stored_version = value
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    if stored_version < u64::from(CURRENT_VERSION)
        && let Some(object) = value.as_object_mut()
    {
        if stored_version < 3 {
            // v3 offers intentionally removed variable price denominators. Drop
            // only stale signed listings; wallet, channels, leases, and sessions
            // remain intact so an upgrade never loses funds or payment history.
            object.insert("offers".to_string(), serde_json::json!({}));
        }
        // v4 adds immutable accepted terms to new channels. Existing channels
        // are retained for accounting/refunds but fail closed without a snapshot.
        // v5 records the exact selected buyer session and its open-attempt time.
        // Serde defaults preserve existing sessions; the daemon selects the newest
        // eligible legacy session once before sending another open request.
        object.insert("version".to_string(), CURRENT_VERSION.into());
    }
    let mut store = match serde_json::from_value::<PaidRouteStore>(value) {
        Ok(store) => store,
        Err(error) => {
            eprintln!(
                "discarding unreadable paid route store {}: {error}",
                path.display()
            );
            return Ok(PaidRouteStore::default());
        }
    };
    store.retain_valid();
    Ok(store)
}

fn write_paid_route_store(path: &Path, store: &PaidRouteStore) -> Result<()> {
    let raw = serde_json::to_string_pretty(store)
        .with_context(|| format!("failed to serialize paid route store {}", path.display()))?;
    crate::config::write_private_file_preserving_user_owner(path, raw.as_bytes())
        .with_context(|| format!("failed to write paid route store {}", path.display()))
}

#[cfg(unix)]
fn preferred_paid_route_lock_owner(path: &Path) -> Option<(u32, u32)> {
    let store_owner = fs::metadata(path)
        .ok()
        .map(|metadata| (metadata.uid(), metadata.gid()));
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent_owner = fs::metadata(parent)
        .ok()
        .map(|metadata| (metadata.uid(), metadata.gid()));
    crate::config::preferred_private_file_owner(store_owner, parent_owner)
}

#[cfg(unix)]
fn repair_paid_route_lock(file: &File, path: &Path, owner: Option<(u32, u32)>) -> Result<()> {
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect paid route lock {}", path.display()))?;
    if let Some((uid, gid)) = owner
        && (metadata.uid(), metadata.gid()) != (uid, gid)
    {
        std::os::unix::fs::fchown(file, Some(uid), Some(gid)).with_context(|| {
            format!(
                "failed to restore user ownership on paid route lock {}",
                path.display()
            )
        })?;
    }
    if metadata.permissions().mode() & 0o777 != 0o600 {
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to protect paid route lock {}", path.display()))?;
    }
    Ok(())
}

/// Exclusively updates the paid-route store across processes and commits it atomically.
pub fn update_paid_route_store<T>(
    path: &Path,
    update: impl FnOnce(&mut PaidRouteStore) -> Result<T>,
) -> Result<T> {
    let lock_path = path.with_extension("json.lock");
    #[cfg(unix)]
    let initial_owner = preferred_paid_route_lock_owner(path);
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    options.custom_flags(libc::O_NOFOLLOW);
    let lock = options.open(&lock_path).with_context(|| {
        format!(
            "failed to open paid route store lock {}",
            lock_path.display()
        )
    })?;
    #[cfg(unix)]
    repair_paid_route_lock(&lock, &lock_path, initial_owner)?;
    lock.lock()
        .with_context(|| format!("failed to lock paid route store {}", path.display()))?;
    #[cfg(unix)]
    repair_paid_route_lock(&lock, &lock_path, preferred_paid_route_lock_owner(path))?;

    let mut store = load_paid_route_store(path)?;
    let original = store.clone();
    let result = update(&mut store)?;
    if store != original {
        write_paid_route_store(path, &store)?;
    }
    Ok(result)
}

#[cfg(all(test, unix))]
mod lock_owner_tests {
    #[test]
    fn lock_owner_tracks_store_then_non_root_parent() {
        assert_eq!(
            crate::config::preferred_private_file_owner(Some((502, 20)), Some((501, 20))),
            Some((502, 20))
        );
        assert_eq!(
            crate::config::preferred_private_file_owner(Some((0, 0)), Some((501, 20))),
            Some((501, 20))
        );
        assert_eq!(
            crate::config::preferred_private_file_owner(None, Some((501, 20))),
            Some((501, 20))
        );
    }
}

pub fn apply_paid_route_seller_payment_file(
    path: &Path,
    request: ApplyPaidRouteSellerPaymentRequest,
) -> Result<ApplyPaidRouteSellerPaymentResult> {
    update_paid_route_store(path, |store| store.apply_seller_payment(request))
}

pub fn acknowledge_paid_route_payment_outbox(
    config_path: &Path,
    seller_pubkey: &str,
    id: &str,
) -> Result<bool> {
    if !valid_paid_route_payment_id(id) {
        return Err(anyhow!("invalid paid route payment acknowledgment id"));
    }
    let path = paid_route_payment_outbox_directory(config_path).join(format!("{id}.json"));
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", path.display()));
        }
    };
    let envelope: StreamingRoutePaymentEnvelope = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to decode {}", path.display()))?;
    let expected_seller = normalize_nostr_pubkey(&envelope.seller)
        .context("invalid paid route payment outbox seller")?;
    let authenticated_seller = normalize_nostr_pubkey(seller_pubkey)
        .context("invalid paid route payment acknowledgment source")?;
    if authenticated_seller != expected_seller {
        return Err(anyhow!(
            "paid route payment acknowledgment source does not match seller"
        ));
    }
    if paid_route_payment_id(&envelope)? != id {
        return Err(anyhow!(
            "paid route payment acknowledgment id does not match outbox envelope"
        ));
    }
    fs::remove_file(&path).with_context(|| format!("failed to remove {}", path.display()))?;
    Ok(true)
}

fn valid_paid_route_payment_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn upsert_paid_route_offer(
    path: &Path,
    signed_offer: SignedPaidRouteOffer,
    relay_urls: Vec<String>,
    seen_at_unix: u64,
) -> Result<bool> {
    update_paid_route_store(path, |store| {
        store.upsert_signed_offer(signed_offer, relay_urls, seen_at_unix)
    })
}

pub fn paid_route_offer_store_key(seller_npub: &str, offer_id: &str) -> String {
    format!("{}:{}", seller_npub.trim(), offer_id.trim())
}

pub(super) fn default_version() -> u8 {
    CURRENT_VERSION
}

pub(super) fn is_zero(value: &u64) -> bool {
    *value == 0
}

pub(super) fn paid_route_offer_autoselect_score(record: &PaidRouteOfferRecord) -> i64 {
    record.rating_score.unwrap_or_default()
}

pub(super) fn normalize_relay_list(values: Vec<String>) -> Vec<String> {
    let mut values = values
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

pub(super) fn merge_sorted_strings(left: &[String], right: Vec<String>) -> Vec<String> {
    let mut out = left.to_vec();
    out.extend(right);
    normalize_relay_list(out)
}

pub(super) fn upsert_record<T: PartialEq>(
    records: &mut BTreeMap<String, T>,
    key: String,
    record: T,
) -> bool {
    if records
        .get(&key)
        .is_some_and(|existing| existing == &record)
    {
        return false;
    }
    records.insert(key, record);
    true
}

pub(super) fn select_buyer_mint(
    offer: &PaidRouteOffer,
    wallet: &PaidRouteWalletState,
    requested: Option<&str>,
) -> Result<String> {
    let accepted_mints = normalize_mint_list(&offer.channel.accepted_mints);
    if let Some(requested) = requested.map(str::trim).filter(|value| !value.is_empty()) {
        if !accepted_mints.is_empty() && !accepted_mints.iter().any(|mint| mint == requested) {
            return Err(anyhow!(
                "Cashu mint {requested} is not accepted by paid route offer {}",
                offer.offer_id
            ));
        }
        if !wallet.mints.iter().any(|mint| mint.url.trim() == requested) {
            return Err(anyhow!(
                "Cashu mint {requested} is not approved in this wallet"
            ));
        }
        return Ok(requested.to_string());
    }

    let default_mint = wallet.default_mint.trim();
    if !default_mint.is_empty()
        && (accepted_mints.is_empty() || accepted_mints.iter().any(|mint| mint == default_mint))
    {
        return Ok(default_mint.to_string());
    }

    if let Some(wallet_mint) = wallet.mints.iter().find(|wallet_mint| {
        let url = wallet_mint.url.trim();
        !url.is_empty()
            && (accepted_mints.is_empty() || accepted_mints.iter().any(|mint| mint == url))
    }) {
        return Ok(wallet_mint.url.trim().to_string());
    }

    if !paid_route_offer_requires_payment(offer) {
        return Ok(String::new());
    }

    Err(anyhow!(
        "paid route offer {} has no accepted mint approved in this wallet",
        offer.offer_id
    ))
}

pub(super) fn requested_channel_capacity(
    offer: &PaidRouteOffer,
    requested: Option<u64>,
) -> Result<u64> {
    let max_capacity = offer.channel.max_channel_capacity_sat.max(1);
    let capacity = requested.unwrap_or(max_capacity);
    if capacity == 0 {
        return Err(anyhow!(
            "paid route channel capacity must be greater than zero"
        ));
    }
    if capacity > max_capacity {
        return Err(anyhow!(
            "paid route channel capacity {capacity} sat exceeds offer maximum {max_capacity} sat"
        ));
    }
    Ok(capacity)
}

pub(super) fn paid_route_offer_requires_payment(offer: &PaidRouteOffer) -> bool {
    offer.pricing.price_msat_per_gb > 0
}

pub(super) fn paid_route_offer_requires_payment_before_routing(offer: &PaidRouteOffer) -> bool {
    paid_route_offer_requires_payment(offer) && offer.channel.free_probe_units == 0
}

pub(super) fn paid_exit_config_requires_payment(config: &PaidExitConfig) -> bool {
    config.pricing.price_msat_per_gb > 0
}

pub(super) fn accepted_channel_terms(
    channel: &PaidRouteChannelRecord,
    role: PaidRouteChannelRole,
) -> Result<&PaidExitConfig> {
    if channel.role != role {
        return Err(anyhow!("paid route channel has the wrong role"));
    }
    channel
        .accepted_terms
        .as_ref()
        .filter(|terms| terms.enabled)
        .ok_or_else(|| {
            anyhow!(
                "paid route channel {} has no accepted terms",
                channel.channel_id
            )
        })
}

pub(super) fn paid_exit_destination_allowed_ips(config: &PaidExitConfig) -> Vec<String> {
    crate::config::exit_node_default_routes()
        .into_iter()
        .filter(|route| {
            (route == "0.0.0.0/0" && config.ip_support.ipv4)
                || (route == "::/0" && config.ip_support.ipv6)
        })
        .collect()
}

pub(super) fn initial_buyer_session_status(
    offer: &PaidRouteOffer,
    initial_paid_msat: u64,
) -> PaidRouteLifecycleStatus {
    if !paid_route_offer_requires_payment(offer) || initial_paid_msat > 0 {
        PaidRouteLifecycleStatus::Active
    } else if offer.channel.free_probe_units > 0 {
        PaidRouteLifecycleStatus::Probing
    } else {
        PaidRouteLifecycleStatus::Opening
    }
}

pub(super) fn initial_seller_session_status(
    config: &PaidExitConfig,
    paid_msat: u64,
) -> PaidRouteLifecycleStatus {
    if !paid_exit_config_requires_payment(config) || paid_msat > 0 {
        PaidRouteLifecycleStatus::Active
    } else if config.channel.free_probe_units > 0 {
        PaidRouteLifecycleStatus::Probing
    } else {
        PaidRouteLifecycleStatus::Opening
    }
}

pub(super) fn paid_route_lifecycle_allows_routing(status: PaidRouteLifecycleStatus) -> bool {
    matches!(
        status,
        PaidRouteLifecycleStatus::Opening
            | PaidRouteLifecycleStatus::Probing
            | PaidRouteLifecycleStatus::Active
    )
}

pub(super) fn paid_route_session_has_payment_material(
    session: &PaidRouteSession,
    channel: &PaidRouteChannelRecord,
) -> bool {
    match session.payment.mode {
        PaidRoutePaymentMode::CashuSpilman => {
            session
                .payment
                .cashu_spilman_payment
                .as_ref()
                .is_some_and(CashuSpilmanPayment::has_funding)
                || channel
                    .payment
                    .cashu_spilman_payment
                    .as_ref()
                    .is_some_and(CashuSpilmanPayment::has_funding)
        }
        PaidRoutePaymentMode::CashuTokenLease => {
            session.payment.cashu_token_lease.is_some()
                || channel.payment.cashu_token_lease.is_some()
        }
    }
}

pub(super) fn preserve_terminal_status(
    current: PaidRouteLifecycleStatus,
    incoming: PaidRouteLifecycleStatus,
) -> PaidRouteLifecycleStatus {
    match current {
        PaidRouteLifecycleStatus::Closing
        | PaidRouteLifecycleStatus::Closed
        | PaidRouteLifecycleStatus::Expired
        | PaidRouteLifecycleStatus::Failed => current,
        _ => incoming,
    }
}

pub(super) fn ensure_open_buyer_channel(
    channel: &PaidRouteChannelRecord,
    lease: &PaidRouteLeaseRecord,
) -> Result<()> {
    if matches!(
        channel.status,
        PaidRouteLifecycleStatus::Closed
            | PaidRouteLifecycleStatus::Closing
            | PaidRouteLifecycleStatus::Expired
            | PaidRouteLifecycleStatus::Failed
    ) {
        return Err(anyhow!(
            "paid route buyer channel {} is not open",
            channel.channel_id
        ));
    }
    if matches!(
        lease.status,
        PaidRouteLifecycleStatus::Closed
            | PaidRouteLifecycleStatus::Closing
            | PaidRouteLifecycleStatus::Expired
            | PaidRouteLifecycleStatus::Failed
    ) {
        return Err(anyhow!(
            "paid route buyer lease {} is not open",
            lease.lease.lease_id
        ));
    }
    Ok(())
}

pub(super) fn ensure_buyer_channel_accepts_payment(
    channel: &PaidRouteChannelRecord,
    lease: &PaidRouteLeaseRecord,
    kind: BuildPaidRouteBuyerPaymentEnvelopeKind,
) -> Result<()> {
    if kind != BuildPaidRouteBuyerPaymentEnvelopeKind::CooperativeClose {
        return ensure_open_buyer_channel(channel, lease);
    }

    if matches!(
        channel.status,
        PaidRouteLifecycleStatus::Expired | PaidRouteLifecycleStatus::Failed
    ) {
        return Err(anyhow!(
            "paid route buyer channel {} cannot be closed",
            channel.channel_id
        ));
    }
    if matches!(
        lease.status,
        PaidRouteLifecycleStatus::Expired | PaidRouteLifecycleStatus::Failed
    ) {
        return Err(anyhow!(
            "paid route buyer lease {} cannot be closed",
            lease.lease.lease_id
        ));
    }
    Ok(())
}

pub(super) fn seller_admission_preferred(
    candidate: &PaidRouteSellerAdmission,
    existing: &PaidRouteSellerAdmission,
) -> bool {
    match (candidate.allow_routing, existing.allow_routing) {
        (true, false) => true,
        (false, true) => false,
        _ => candidate.updated_at_unix > existing.updated_at_unix,
    }
}

pub(super) fn validate_seller_open_payment(
    config: &PaidExitConfig,
    _seller_pubkey_hex: &str,
    channel_id: &str,
    open: &cashu_service::StreamingRouteChannelOpen,
) -> Result<()> {
    let mint_url = open.mint_url.trim();
    if paid_exit_config_requires_payment(config) {
        let accepted_mints = normalize_mint_list(&config.channel.accepted_mints);
        if accepted_mints.is_empty() {
            return Err(anyhow!(
                "paid exit seller config must accept at least one Cashu mint"
            ));
        }
        if !accepted_mints.iter().any(|mint| mint == mint_url) {
            return Err(anyhow!(
                "Cashu mint {mint_url} is not accepted by this paid exit"
            ));
        }
    }

    let capacity_sat = paid_route_channel_capacity_sat(&open.unit, open.capacity)?;
    if capacity_sat == 0 {
        return Err(anyhow!(
            "paid route channel capacity must be greater than zero"
        ));
    }
    if capacity_sat > config.channel.max_channel_capacity_sat {
        return Err(anyhow!(
            "paid route channel capacity {capacity_sat} sat exceeds seller maximum {} sat",
            config.channel.max_channel_capacity_sat
        ));
    }
    validate_paid_route_payment_progress(
        "paid route opening balance",
        open.paid_msat,
        0,
        capacity_sat,
    )?;
    validate_streaming_route_cashu_payment_claim(
        &open.payment,
        channel_id,
        &open.unit,
        open.paid_msat,
        capacity_sat,
        true,
    )
    .map_err(|error| anyhow!("{error}"))?;
    if open.receiver_pubkey_hex.trim().is_empty() {
        return Err(anyhow!("paid route channel receiver pubkey is empty"));
    }
    normalize_paid_route_receiver_pubkey(open.receiver_pubkey_hex.trim())
        .map_err(|error| anyhow!("invalid paid route channel receiver pubkey: {error}"))?;
    Ok(())
}

pub(super) fn paid_route_offer_receiver_pubkey_hex(
    offer: &PaidRouteOffer,
    seller_pubkey: &PublicKey,
) -> Result<String> {
    if offer.receiver_pubkey_hex.trim().is_empty() {
        return Ok(seller_pubkey.to_hex());
    }
    normalize_paid_route_receiver_pubkey(&offer.receiver_pubkey_hex)
}

pub(super) fn normalize_paid_route_receiver_pubkey(value: &str) -> Result<String> {
    let trimmed = value.trim();
    let hex = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if hex.len() == 66
        && matches!(&hex[..2], "02" | "03")
        && hex.chars().all(|ch| ch.is_ascii_hexdigit())
    {
        return Ok(hex.to_ascii_lowercase());
    }
    if hex.len() == 64 && hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Ok(hex.to_ascii_lowercase());
    }
    Err(anyhow!("invalid paid route receiver pubkey"))
}

pub(super) fn validate_seller_token_lease(
    config: &PaidExitConfig,
    token_lease: &StreamingRouteCashuTokenLease,
    now_unix: u64,
) -> Result<()> {
    let normalized =
        create_streaming_route_cashu_token_lease(StreamingRouteCashuTokenLeaseRequest {
            channel_id: token_lease.channel_id.clone(),
            mint_url: token_lease.mint_url.clone(),
            unit: token_lease.unit.clone(),
            amount: token_lease.amount,
            paid_msat: Some(token_lease.paid_msat),
            expires_unix: token_lease.expires_unix,
            token: token_lease.token.clone(),
        })
        .map_err(|error| anyhow!("{error}"))?;
    if normalized.expires_unix <= now_unix {
        return Err(anyhow!("paid route token lease is already expired"));
    }

    let mint_url = normalized.mint_url.trim();
    if paid_exit_config_requires_payment(config) {
        let accepted_mints = normalize_mint_list(&config.channel.accepted_mints);
        if accepted_mints.is_empty() {
            return Err(anyhow!(
                "paid exit seller config must accept at least one Cashu mint"
            ));
        }
        if !accepted_mints.iter().any(|mint| mint == mint_url) {
            return Err(anyhow!(
                "Cashu mint {mint_url} is not accepted by this paid exit"
            ));
        }
    }

    let capacity_sat = paid_route_channel_capacity_sat(&normalized.unit, normalized.amount)?;
    if capacity_sat == 0 {
        return Err(anyhow!(
            "paid route token lease amount must be greater than zero"
        ));
    }
    if capacity_sat > config.channel.max_channel_capacity_sat {
        return Err(anyhow!(
            "paid route token lease amount {capacity_sat} sat exceeds seller maximum {} sat",
            config.channel.max_channel_capacity_sat
        ));
    }
    Ok(())
}

pub(super) fn paid_route_channel_capacity_sat(unit: &str, capacity: u64) -> Result<u64> {
    streaming_route_cashu_capacity_sat(unit, capacity).map_err(|error| anyhow!("{error}"))
}

pub(super) fn paid_route_payment_cashu_unit(payment: &PaidRoutePaymentState) -> String {
    let unit = payment.cashu_unit.trim();
    if unit.is_empty() {
        "sat".to_string()
    } else {
        unit.to_string()
    }
}

pub(super) fn cashu_payment_balance_msat(unit: &str, balance: u64) -> Result<u64> {
    streaming_route_cashu_balance_msat(unit, balance).map_err(|error| anyhow!("{error}"))
}

pub(super) fn cashu_payment_target_msat(unit: &str, paid_msat: u64) -> Result<u64> {
    let balance = streaming_route_cashu_balance_for_msat(unit, paid_msat)
        .map_err(|error| anyhow!("{error}"))?;
    cashu_payment_balance_msat(unit, balance)
}

pub(super) fn validate_cashu_spilman_payment_claim(
    payment: &CashuSpilmanPayment,
    channel_id: &str,
    unit: &str,
    paid_msat: u64,
    capacity_sat: u64,
    require_funding: bool,
) -> Result<()> {
    validate_streaming_route_cashu_payment_claim(
        payment,
        channel_id,
        unit,
        paid_msat,
        capacity_sat,
        require_funding,
    )
    .map(|_| ())
    .map_err(|error| anyhow!("{error}"))
}

pub(super) fn cashu_channel_capacity_for_unit(capacity_sat: u64, unit: &str) -> Result<u64> {
    streaming_route_cashu_capacity_for_sat(unit, capacity_sat).map_err(|error| anyhow!("{error}"))
}

pub(super) fn validate_paid_route_payment_progress(
    label: &str,
    paid_msat: u64,
    previous_paid_msat: u64,
    capacity_sat: u64,
) -> Result<()> {
    validate_streaming_route_cashu_payment_progress(
        label,
        paid_msat,
        previous_paid_msat,
        capacity_sat,
    )
    .map(|_| ())
    .map_err(|error| anyhow!("{error}"))
}

pub(super) fn seller_channel_open_expiry(
    now_unix: u64,
    configured_expiry_secs: u64,
    requested_expires_unix: u64,
) -> Result<u64> {
    let configured = now_unix.saturating_add(configured_expiry_secs.max(1));
    let expires_at_unix = if requested_expires_unix == 0 {
        configured
    } else {
        configured.min(requested_expires_unix)
    };
    if expires_at_unix <= now_unix {
        return Err(anyhow!("paid route channel opening is already expired"));
    }
    Ok(expires_at_unix)
}

pub(super) fn seller_quote_id_for_lease(lease_id: &str) -> String {
    format!("seller-quote-{}", sanitize_id_component(lease_id))
}

pub(super) fn seller_session_id_for_lease(lease_id: &str) -> String {
    format!("seller-session-{}", sanitize_id_component(lease_id))
}

pub(super) fn paid_route_payment_payload_type(
    payload: &StreamingRoutePaymentPayload,
) -> &'static str {
    match payload {
        StreamingRoutePaymentPayload::ChannelOpen(_) => "channel_open",
        StreamingRoutePaymentPayload::BalanceUpdate(_) => "balance_update",
        StreamingRoutePaymentPayload::CooperativeClose(_) => "cooperative_close",
        StreamingRoutePaymentPayload::CooperativeCloseAck(_) => "cooperative_close_ack",
        StreamingRoutePaymentPayload::CashuTokenLease(_) => "cashu_token_lease",
    }
}

pub(super) fn trimmed_required(value: &str, label: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        Err(anyhow!("{label} is empty"))
    } else {
        Ok(value.to_string())
    }
}

pub(super) fn normalize_optional_probe_string(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(super) fn normalize_optional_country_code(value: Option<String>) -> Option<String> {
    normalize_optional_probe_string(value).map(|value| value.to_ascii_uppercase())
}

pub(super) fn ensure_seller_channel_matches(
    channel: &PaidRouteChannelRecord,
    service_id: &str,
    buyer_npub: &str,
) -> Result<()> {
    if channel.role != PaidRouteChannelRole::Seller {
        return Err(anyhow!(
            "paid route channel {} is not a seller channel",
            channel.channel_id
        ));
    }
    if channel.offer_id != service_id {
        return Err(anyhow!(
            "paid route channel {} belongs to service {}, not {}",
            channel.channel_id,
            channel.offer_id,
            service_id
        ));
    }
    if normalize_paid_route_npub(&channel.counterparty_npub, "buyer")? != buyer_npub {
        return Err(anyhow!(
            "paid route payment buyer does not match channel counterparty"
        ));
    }
    Ok(())
}

pub(super) fn apply_delivered_bytes(usage: &mut PaidRouteUsage, delivered_bytes: u64) {
    usage.billable_bytes = usage.billable_bytes.max(delivered_bytes);
}

pub(super) fn paid_route_amount_due_for_delivered_units(
    config: &PaidExitConfig,
    usage: &PaidRouteUsage,
    delivered_units: u64,
) -> u64 {
    let mut usage = usage.clone();
    apply_delivered_bytes(&mut usage, delivered_units);
    config.amount_due_msat(&usage)
}

pub(super) fn apply_usage_delta(usage: &mut PaidRouteUsage, delta: &PaidRouteUsage) {
    usage.add_assign(delta);
}

pub(super) fn paid_route_buyer_session_id_suffix(
    offer_key: &str,
    offer_id: &str,
    now_unix: u64,
) -> String {
    let mut hasher = DefaultHasher::new();
    offer_key.hash(&mut hasher);
    offer_id.hash(&mut hasher);
    now_unix.hash(&mut hasher);
    let readable = sanitize_id_component(offer_id);
    format!("{readable}-{now_unix}-{:016x}", hasher.finish())
}

pub(super) fn sanitize_id_component(value: &str) -> String {
    let mut out = value
        .trim()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    while out.contains("--") {
        out = out.replace("--", "-");
    }
    out = out.trim_matches('-').to_string();
    if out.is_empty() {
        "route".to_string()
    } else if out.len() > 48 {
        out.chars().take(48).collect()
    } else {
        out
    }
}

pub(super) fn normalize_mint_list(values: &[String]) -> Vec<String> {
    let mut values = values
        .iter()
        .flat_map(|value| value.split([',', '\n', '\r', '\t']))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

pub(super) fn normalize_paid_route_npub(value: &str, role: &str) -> Result<String> {
    let public_key = PublicKey::parse(value.trim())
        .map_err(|error| anyhow!("invalid paid route {role} npub: {error}"))?;
    public_key
        .to_bech32()
        .context("failed to encode paid route npub")
}
