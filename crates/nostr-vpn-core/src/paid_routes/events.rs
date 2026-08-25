use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaidRouteOffer {
    pub offer_id: String,
    pub seller_npub: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub receiver_pubkey_hex: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fips_endpoints: Vec<String>,
    #[serde(default)]
    pub service: PaidRouteServiceKind,
    #[serde(default)]
    pub access: PaidRouteAccessPolicy,
    #[serde(default)]
    pub pricing: PaidRoutePricing,
    #[serde(default)]
    pub channel: PaidRouteChannelTerms,
    #[serde(default)]
    pub location: PaidRouteLocationHint,
    #[serde(default)]
    pub ip_support: PaidRouteIpSupport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quality: Option<PaidRouteQualityMetrics>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaidRouteSessionOpen {
    pub version: String,
    pub service_id: String,
    pub lease_id: String,
    pub channel_id: String,
    pub seller_npub: String,
    pub buyer_tunnel_ip: String,
    pub expires_at_unix: u64,
}

impl PaidRouteOffer {
    pub fn from_paid_exit_config(
        offer_id: impl Into<String>,
        seller_npub: impl Into<String>,
        config: &PaidExitConfig,
        quality: Option<PaidRouteQualityMetrics>,
    ) -> Self {
        Self::from_paid_exit_config_with_receiver(offer_id, seller_npub, config, None, quality)
    }

    pub fn from_paid_exit_config_with_receiver(
        offer_id: impl Into<String>,
        seller_npub: impl Into<String>,
        config: &PaidExitConfig,
        receiver_pubkey_hex: Option<&str>,
        quality: Option<PaidRouteQualityMetrics>,
    ) -> Self {
        Self::from_paid_exit_config_with_receiver_and_fips_endpoints(
            offer_id,
            seller_npub,
            config,
            receiver_pubkey_hex,
            &[],
            quality,
        )
    }

    pub fn from_paid_exit_config_with_receiver_and_fips_endpoints(
        offer_id: impl Into<String>,
        seller_npub: impl Into<String>,
        config: &PaidExitConfig,
        receiver_pubkey_hex: Option<&str>,
        fips_endpoints: &[String],
        quality: Option<PaidRouteQualityMetrics>,
    ) -> Self {
        let mut config = config.clone();
        config.normalize();
        Self {
            offer_id: offer_id.into(),
            seller_npub: seller_npub.into(),
            receiver_pubkey_hex: receiver_pubkey_hex
                .map(normalize_receiver_pubkey_hex_lossy)
                .unwrap_or_default(),
            fips_endpoints: normalize_offer_fips_endpoints_lossy(fips_endpoints),
            service: PaidRouteServiceKind::InternetExit,
            access: config.access.clone(),
            pricing: config.pricing.clone(),
            channel: config.channel.clone(),
            location: config.location.clone(),
            ip_support: config.ip_support.clone(),
            quality,
        }
    }
}

pub fn signed_paid_exit_offer_from_config(
    offer_id: impl Into<String>,
    keys: &Keys,
    config: &PaidExitConfig,
    quality: Option<PaidRouteQualityMetrics>,
    signed_at: u64,
) -> Result<SignedPaidRouteOffer> {
    signed_paid_exit_offer_from_config_with_receiver(
        offer_id, keys, config, None, quality, signed_at,
    )
}

pub fn signed_paid_exit_offer_from_config_with_receiver(
    offer_id: impl Into<String>,
    keys: &Keys,
    config: &PaidExitConfig,
    receiver_pubkey_hex: Option<&str>,
    quality: Option<PaidRouteQualityMetrics>,
    signed_at: u64,
) -> Result<SignedPaidRouteOffer> {
    signed_paid_exit_offer_from_config_with_receiver_and_fips_endpoints(
        offer_id,
        keys,
        config,
        receiver_pubkey_hex,
        &[],
        quality,
        signed_at,
    )
}

pub fn signed_paid_exit_offer_from_config_with_receiver_and_fips_endpoints(
    offer_id: impl Into<String>,
    keys: &Keys,
    config: &PaidExitConfig,
    receiver_pubkey_hex: Option<&str>,
    fips_endpoints: &[String],
    quality: Option<PaidRouteQualityMetrics>,
    signed_at: u64,
) -> Result<SignedPaidRouteOffer> {
    if !config.enabled {
        return Err(anyhow!("paid exit selling is disabled"));
    }
    let mut normalized_config = config.clone();
    normalized_config.normalize();
    if normalized_config.pricing.price_msat_per_gb > 0
        && normalized_config.channel.accepted_mints.is_empty()
    {
        return Err(anyhow!(
            "paid exit offers with non-zero pricing require at least one accepted Cashu mint"
        ));
    }

    let receiver_pubkey_hex = receiver_pubkey_hex
        .map(normalize_receiver_pubkey_hex)
        .transpose()?;
    let normalized_fips_endpoints = normalize_offer_fips_endpoints(fips_endpoints)?;
    let offer = PaidRouteOffer::from_paid_exit_config_with_receiver_and_fips_endpoints(
        offer_id,
        public_key_npub(&keys.public_key())?,
        &normalized_config,
        receiver_pubkey_hex.as_deref(),
        &normalized_fips_endpoints,
        quality,
    );
    SignedPaidRouteOffer::sign(offer, keys, signed_at)
}

pub fn paid_route_offer_filter(limit: usize, since_unix: Option<u64>) -> Filter {
    let mut filter = Filter::new().kind(Kind::Custom(PAID_ROUTE_OFFER_KIND));
    if limit > 0 {
        filter = filter.limit(limit);
    }
    if let Some(since_unix) = since_unix {
        filter = filter.since(Timestamp::from(since_unix));
    }
    filter
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPaidRouteOffer {
    pub event: Event,
}

impl SignedPaidRouteOffer {
    pub fn sign(offer: PaidRouteOffer, keys: &Keys, signed_at: u64) -> Result<Self> {
        Self::sign_expiring_at(
            offer,
            keys,
            signed_at,
            signed_at.saturating_add(PAID_ROUTE_OFFER_TTL_SECS),
        )
    }

    pub fn sign_expiring_at(
        offer: PaidRouteOffer,
        keys: &Keys,
        signed_at: u64,
        expires_at: u64,
    ) -> Result<Self> {
        if expires_at < signed_at {
            return Err(anyhow!(
                "paid route offer expiration cannot precede its creation"
            ));
        }
        validate_paid_route_offer(&offer)?;
        let content = serde_json::to_string(&offer).context("failed to encode paid route offer")?;
        let mut tags = paid_route_offer_tags(&offer)?;
        tags.push(Tag::expiration(Timestamp::from(expires_at)));
        let event = EventBuilder::new(Kind::Custom(PAID_ROUTE_OFFER_KIND), content)
            .tags(tags)
            .custom_created_at(Timestamp::from(signed_at))
            .sign_with_keys(keys)
            .map_err(|error| anyhow!("failed to sign paid route offer: {error}"))?;
        let signed = Self { event };
        signed.verify()?;
        Ok(signed)
    }

    pub fn from_event(event: Event) -> Result<Self> {
        let signed = Self { event };
        signed.verify()?;
        Ok(signed)
    }

    pub fn verify(&self) -> Result<()> {
        if u16::from(self.event.kind) != PAID_ROUTE_OFFER_KIND {
            return Err(anyhow!(
                "unexpected paid route offer event kind {}",
                u16::from(self.event.kind)
            ));
        }
        self.event
            .verify()
            .map_err(|error| anyhow!("invalid paid route offer signature: {error}"))?;
        let offer = self.offer()?;
        validate_paid_route_offer(&offer)?;
        let signer_npub = public_key_npub(&self.event.pubkey)?;
        let offer_seller_npub = normalize_npub(&offer.seller_npub, "seller")?;
        if signer_npub != offer_seller_npub {
            return Err(anyhow!(
                "paid route offer seller does not match event signer"
            ));
        }
        validate_paid_route_offer_tags(self.event.tags.as_slice(), &offer)?;
        Ok(())
    }

    pub fn offer(&self) -> Result<PaidRouteOffer> {
        serde_json::from_str(&self.event.content).context("failed to decode paid route offer")
    }

    pub fn is_live_at(&self, now_unix: u64) -> bool {
        let signed_at = self.event.created_at.as_secs();
        if signed_at > now_unix.saturating_add(PAID_ROUTE_OFFER_FUTURE_SKEW_SECS) {
            return false;
        }
        let protocol_expiry = signed_at.saturating_add(PAID_ROUTE_OFFER_TTL_SECS);
        let expiry = self
            .event
            .tags
            .expiration()
            .map(|expiry| expiry.as_secs().min(protocol_expiry))
            .unwrap_or(protocol_expiry);
        now_unix < expiry
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaidRouteQuote {
    pub quote_id: String,
    pub offer_id: String,
    #[serde(default)]
    pub payment_mode: PaidRoutePaymentMode,
    pub channel_capacity_sat: u64,
    pub expires_at_unix: u64,
    pub receiver_pubkey_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaidRouteLease {
    pub lease_id: String,
    pub offer_id: String,
    pub quote_id: String,
    pub buyer_npub: String,
    pub starts_at_unix: u64,
    pub expires_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PaidRoutePaymentState {
    #[serde(default)]
    pub mode: PaidRoutePaymentMode,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub channel_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cashu_unit: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub capacity_sat: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub paid_msat: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub updated_at_unix: u64,
    #[cfg(feature = "paid-exit")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cashu_spilman_payment: Option<CashuSpilmanPayment>,
    #[cfg(feature = "paid-exit")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cashu_token_lease: Option<StreamingRouteCashuTokenLease>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaidRouteSession {
    pub session_id: String,
    pub lease_id: String,
    #[serde(default)]
    pub usage: PaidRouteUsage,
    #[serde(default)]
    pub payment: PaidRoutePaymentState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realized_exit_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_country_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_asn: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quality: Option<PaidRouteQualityMetrics>,
}

impl PaidRouteSession {
    pub fn routing_decision(&self, config: &PaidExitConfig) -> PaidRouteRoutingDecision {
        config.routing_decision(&self.usage, self.payment.paid_msat)
    }

    pub fn can_continue_routing(&self, config: &PaidExitConfig) -> bool {
        self.routing_decision(config).allow_routing
    }
}

pub(super) fn paid_route_offer_tags(offer: &PaidRouteOffer) -> Result<Vec<Tag>> {
    let mut tags = vec![
        Tag::identifier(offer.offer_id.trim().to_string()),
        paid_route_tag(&["app", PAID_ROUTE_OFFER_APP])?,
        paid_route_tag(&["v", PAID_ROUTE_OFFER_VERSION])?,
        paid_route_tag(&["service", offer.service.as_str()])?,
        paid_route_tag(&["payment", PaidRoutePaymentMode::CashuSpilman.as_str()])?,
        paid_route_owned_tag(vec![
            "price_msat_per_gb".to_string(),
            offer.pricing.price_msat_per_gb.to_string(),
        ])?,
        paid_route_owned_tag(vec![
            "max_channel_capacity_sat".to_string(),
            offer.channel.max_channel_capacity_sat.to_string(),
        ])?,
        paid_route_owned_tag(vec![
            "channel_expiry_secs".to_string(),
            offer.channel.channel_expiry_secs.to_string(),
        ])?,
        paid_route_number_tag("free_probe_units", offer.channel.free_probe_units)?,
        paid_route_number_tag("grace_units", offer.channel.grace_units)?,
        paid_route_tag(&["upstream", offer.access.upstream.as_str()])?,
        paid_route_tag(&[
            "private_vpn_access",
            offer.access.private_vpn_access.as_str(),
        ])?,
    ];

    if !offer.receiver_pubkey_hex.trim().is_empty() {
        tags.push(paid_route_owned_tag(vec![
            "receiver_pubkey".to_string(),
            normalize_receiver_pubkey_hex(&offer.receiver_pubkey_hex)?,
        ])?);
    }

    for endpoint in &offer.fips_endpoints {
        tags.push(paid_route_owned_tag(vec![
            "fips_endpoint".to_string(),
            endpoint.clone(),
        ])?);
    }

    for mint in normalize_string_list(&offer.channel.accepted_mints) {
        tags.push(paid_route_owned_tag(vec!["mint".to_string(), mint])?);
    }
    if !offer.location.country_code.trim().is_empty() {
        tags.push(paid_route_tag(&[
            "country",
            offer.location.country_code.trim(),
        ])?);
    }
    if let Some(asn) = offer.location.asn {
        tags.push(paid_route_owned_tag(vec![
            "asn".to_string(),
            asn.to_string(),
        ])?);
    }
    if offer.ip_support.ipv4 {
        tags.push(paid_route_tag(&["ip", "ipv4"])?);
    }
    if offer.ip_support.ipv6 {
        tags.push(paid_route_tag(&["ip", "ipv6"])?);
    }
    if let Some(quality) = &offer.quality {
        if let Some(latency_ms) = quality.latency_ms {
            tags.push(paid_route_number_tag("latency_ms", latency_ms)?);
        }
        if let Some(jitter_ms) = quality.jitter_ms {
            tags.push(paid_route_number_tag("jitter_ms", jitter_ms)?);
        }
        if let Some(packet_loss_ppm) = quality.packet_loss_ppm {
            tags.push(paid_route_number_tag("packet_loss_ppm", packet_loss_ppm)?);
        }
        if let Some(down_bps) = quality.down_bps {
            tags.push(paid_route_number_tag("down_bps", down_bps)?);
        }
        if let Some(up_bps) = quality.up_bps {
            tags.push(paid_route_number_tag("up_bps", up_bps)?);
        }
        if let Some(uptime_secs) = quality.uptime_secs {
            tags.push(paid_route_number_tag("uptime_secs", uptime_secs)?);
        }
        if let Some(last_seen_unix) = quality.last_seen_unix {
            tags.push(paid_route_number_tag("last_seen_unix", last_seen_unix)?);
        }
    }

    Ok(tags)
}

fn paid_route_number_tag(name: &str, value: impl ToString) -> Result<Tag> {
    paid_route_owned_tag(vec![name.to_string(), value.to_string()])
}

pub(super) fn paid_route_tag(parts: &[&str]) -> Result<Tag> {
    Tag::parse(parts.iter().copied())
        .map_err(|error| anyhow!("failed to build paid route tag: {error}"))
}

fn paid_route_owned_tag(parts: Vec<String>) -> Result<Tag> {
    Tag::parse(parts).map_err(|error| anyhow!("failed to build paid route tag: {error}"))
}

fn validate_paid_route_offer(offer: &PaidRouteOffer) -> Result<()> {
    if offer.offer_id.trim().is_empty() {
        return Err(anyhow!("paid route offer id is empty"));
    }
    let _ = normalize_npub(&offer.seller_npub, "seller")?;
    if offer.access.private_vpn_access != PaidRoutePrivateVpnAccess::Denied {
        return Err(anyhow!(
            "paid public exit offers must deny private VPN access"
        ));
    }
    if offer.service != PaidRouteServiceKind::InternetExit {
        return Err(anyhow!("unsupported paid route service"));
    }
    if offer.channel.max_channel_capacity_sat == 0 {
        return Err(anyhow!(
            "paid route max channel capacity must be greater than zero"
        ));
    }
    if offer.channel.channel_expiry_secs == 0 {
        return Err(anyhow!(
            "paid route channel expiry must be greater than zero"
        ));
    }
    Ok(())
}

fn validate_paid_route_offer_tags(tags: &[Tag], offer: &PaidRouteOffer) -> Result<()> {
    let mut app_ok = false;
    let mut version_ok = false;
    let mut id_ok = false;
    let mut service_ok = false;
    let mut payment_ok = false;
    let mut upstream_ok = false;
    let mut access_ok = false;
    let mut receiver_ok = offer.receiver_pubkey_hex.trim().is_empty();
    let offer_receiver_pubkey_hex = if offer.receiver_pubkey_hex.trim().is_empty() {
        String::new()
    } else {
        normalize_receiver_pubkey_hex(&offer.receiver_pubkey_hex)?
    };
    let mut remaining_fips_endpoints = offer.fips_endpoints.clone();

    for tag in tags {
        let parts = tag.as_slice();
        let Some(kind) = parts.first().map(String::as_str) else {
            continue;
        };
        match kind {
            "d" => id_ok |= parts.get(1).is_some_and(|value| value == &offer.offer_id),
            "app" => {
                app_ok |= parts
                    .get(1)
                    .is_some_and(|value| value == PAID_ROUTE_OFFER_APP)
            }
            "v" => {
                version_ok |= parts
                    .get(1)
                    .is_some_and(|value| value == PAID_ROUTE_OFFER_VERSION)
            }
            "service" => {
                let Some(value) = parts.get(1) else {
                    return Err(anyhow!("paid route offer event has empty service tag"));
                };
                if value != offer.service.as_str() {
                    return Err(anyhow!(
                        "paid route offer event service tag does not match content"
                    ));
                }
                service_ok = true;
            }
            "payment" => {
                let Some(value) = parts.get(1) else {
                    return Err(anyhow!("paid route offer event has empty payment tag"));
                };
                if value != PaidRoutePaymentMode::CashuSpilman.as_str() {
                    return Err(anyhow!(
                        "paid route offer event payment tag does not match default mode"
                    ));
                }
                payment_ok = true;
            }
            "upstream" => {
                let Some(value) = parts.get(1) else {
                    return Err(anyhow!("paid route offer event has empty upstream tag"));
                };
                if value != offer.access.upstream.as_str() {
                    return Err(anyhow!(
                        "paid route offer event upstream tag does not match content"
                    ));
                }
                upstream_ok = true;
            }
            "private_vpn_access" => {
                let Some(value) = parts.get(1) else {
                    return Err(anyhow!(
                        "paid route offer event has empty private access tag"
                    ));
                };
                if value != "denied" {
                    return Err(anyhow!(
                        "paid route offer event advertises private VPN access"
                    ));
                }
                access_ok = true;
            }
            "receiver_pubkey" => {
                let Some(value) = parts.get(1) else {
                    return Err(anyhow!(
                        "paid route offer event has empty receiver pubkey tag"
                    ));
                };
                let tag_receiver_pubkey_hex = normalize_receiver_pubkey_hex(value)?;
                if tag_receiver_pubkey_hex != offer_receiver_pubkey_hex {
                    return Err(anyhow!(
                        "paid route offer event receiver pubkey tag does not match content"
                    ));
                }
                receiver_ok = true;
            }
            "fips_endpoint" => {
                let Some(value) = parts.get(1) else {
                    return Err(anyhow!("paid route offer has an empty FIPS endpoint tag"));
                };
                let endpoint = normalize_fips_peer_endpoint_hint(value)
                    .ok_or_else(|| anyhow!("paid route offer has an invalid FIPS endpoint tag"))?;
                let Some(index) = remaining_fips_endpoints
                    .iter()
                    .position(|candidate| candidate == &endpoint)
                else {
                    return Err(anyhow!(
                        "paid route offer FIPS endpoint tag does not match content"
                    ));
                };
                remaining_fips_endpoints.remove(index);
            }
            _ => {}
        }
    }

    if !id_ok {
        return Err(anyhow!("paid route offer event is missing matching d tag"));
    }
    if !app_ok {
        return Err(anyhow!("paid route offer event is missing app tag"));
    }
    if !version_ok {
        return Err(anyhow!("paid route offer event is missing version tag"));
    }
    if !service_ok {
        return Err(anyhow!("paid route offer event is missing service tag"));
    }
    if !payment_ok {
        return Err(anyhow!("paid route offer event is missing payment tag"));
    }
    if !upstream_ok {
        return Err(anyhow!("paid route offer event is missing upstream tag"));
    }
    if !access_ok {
        return Err(anyhow!(
            "paid route offer event is missing private access denial tag"
        ));
    }
    if !receiver_ok {
        return Err(anyhow!(
            "paid route offer event is missing matching receiver pubkey tag"
        ));
    }
    if !remaining_fips_endpoints.is_empty() {
        return Err(anyhow!(
            "paid route offer is missing matching FIPS endpoint tags"
        ));
    }
    Ok(())
}

fn normalize_offer_fips_endpoints(values: &[String]) -> Result<Vec<String>> {
    let mut normalized = Vec::new();
    for value in values {
        let endpoint = normalize_fips_peer_endpoint_hint(value).ok_or_else(|| {
            anyhow!("paid route offer contains an invalid FIPS endpoint: {value}")
        })?;
        if !normalized.contains(&endpoint) {
            normalized.push(endpoint);
        }
    }
    normalized.sort();
    Ok(normalized)
}

fn normalize_offer_fips_endpoints_lossy(values: &[String]) -> Vec<String> {
    let mut normalized = values
        .iter()
        .filter_map(|value| normalize_fips_peer_endpoint_hint(value))
        .collect::<Vec<_>>();
    normalized.sort();
    normalized.dedup();
    normalized
}

fn normalize_receiver_pubkey_hex(value: &str) -> Result<String> {
    let trimmed = value.trim();
    let hex = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if hex.len() == 64 && hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Ok(format!("02{}", hex.to_ascii_lowercase()));
    }
    if hex.len() == 66
        && matches!(&hex[..2], "02" | "03")
        && hex.chars().all(|ch| ch.is_ascii_hexdigit())
    {
        return Ok(hex.to_ascii_lowercase());
    }
    Err(anyhow!("invalid paid route receiver pubkey"))
}

fn normalize_receiver_pubkey_hex_lossy(value: &str) -> String {
    normalize_receiver_pubkey_hex(value).unwrap_or_default()
}

fn normalize_npub(value: &str, role: &str) -> Result<String> {
    let public_key = PublicKey::parse(value.trim())
        .map_err(|error| anyhow!("invalid paid route {role} npub: {error}"))?;
    public_key
        .to_bech32()
        .context("failed to encode paid route npub")
}

fn public_key_npub(public_key: &PublicKey) -> Result<String> {
    public_key
        .to_bech32()
        .context("failed to encode paid route event signer npub")
}
