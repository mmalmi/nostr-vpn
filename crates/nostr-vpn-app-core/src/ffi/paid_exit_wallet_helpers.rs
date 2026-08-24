#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PaidRouteTopUpActivityStatus {
    Complete,
    Expired,
    Pending,
}

#[cfg(test)]
fn paid_route_top_up_activity_status(
    value: &serde_json::Value,
    quote_id: &str,
) -> Option<PaidRouteTopUpActivityStatus> {
    value
        .get("activity")?
        .as_array()?
        .iter()
        .find(|entry| {
            json_string(entry, "kind") == "top_up" && json_string(entry, "quote_id") == quote_id
        })
        .and_then(|entry| match json_string(entry, "status").as_str() {
            "complete" => Some(PaidRouteTopUpActivityStatus::Complete),
            "expired" => Some(PaidRouteTopUpActivityStatus::Expired),
            "pending" => Some(PaidRouteTopUpActivityStatus::Pending),
            _ => None,
        })
}

fn cashu_top_up_activity_status(
    activity: &[cashu_service::CashuWalletActivityEntry],
    quote_id: &str,
) -> Option<PaidRouteTopUpActivityStatus> {
    activity
        .iter()
        .find(|entry| {
            entry.kind == cashu_service::CashuWalletActivityKind::TopUp
                && entry.quote_id.as_deref() == Some(quote_id)
        })
        .map(|entry| match entry.status {
            cashu_service::CashuWalletActivityStatus::Complete => {
                PaidRouteTopUpActivityStatus::Complete
            }
            cashu_service::CashuWalletActivityStatus::Expired
            | cashu_service::CashuWalletActivityStatus::Reclaimed => {
                PaidRouteTopUpActivityStatus::Expired
            }
            cashu_service::CashuWalletActivityStatus::Pending => {
                PaidRouteTopUpActivityStatus::Pending
            }
        })
}

#[cfg(any(target_os = "ios", target_os = "android"))]
fn paid_route_wallet_channel_open_request(
    store: &PaidRouteStore,
    session_id: &str,
    mint_url: Option<&str>,
    paid_msat: Option<u64>,
    max_amount_per_output: Option<u64>,
    keyset_id: Option<&str>,
) -> Result<cashu_service::StreamingRouteOpenCashuSpilmanChannelFromWalletRequest> {
    let session_record = store
        .sessions
        .get(session_id)
        .ok_or_else(|| anyhow!("paid exit buyer session {session_id} does not exist"))?;
    let lease_record = store
        .leases
        .get(&session_record.session.lease_id)
        .ok_or_else(|| anyhow!("paid exit lease does not exist"))?;
    let channel_record = store
        .channels
        .get(&session_record.session.payment.channel_id)
        .ok_or_else(|| anyhow!("paid exit channel does not exist"))?;
    let quote_record = store
        .quotes
        .get(&lease_record.lease.quote_id)
        .ok_or_else(|| anyhow!("paid exit quote does not exist"))?;
    let mint_url = mint_url
        .map(str::trim)
        .filter(|mint| !mint.is_empty())
        .map_or_else(|| channel_record.mint_url.clone(), ToOwned::to_owned);
    if mint_url.trim().is_empty() {
        return Err(anyhow!("paid exit session has no Cashu mint"));
    }
    let unit = if session_record.session.payment.cashu_unit.trim().is_empty() {
        "sat".to_string()
    } else {
        session_record.session.payment.cashu_unit.clone()
    };

    Ok(
        cashu_service::StreamingRouteOpenCashuSpilmanChannelFromWalletRequest {
            mint_url,
            receiver_pubkey_hex: quote_record.quote.receiver_pubkey_hex.clone(),
            capacity_sat: session_record.session.payment.capacity_sat,
            expiry_unix: channel_record.expires_at_unix,
            max_amount_per_output: max_amount_per_output.unwrap_or_default(),
            unit,
            opening_paid_msat: paid_msat.unwrap_or(session_record.session.payment.paid_msat),
            keyset_id: keyset_id
                .map(str::trim)
                .filter(|keyset_id| !keyset_id.is_empty())
                .map(ToOwned::to_owned),
            keyset_info_json: None,
        },
    )
}

fn inspect_paid_route_wallet_token(token_text: &str) -> Result<PaidRouteWalletTokenPreview> {
    use cashu::nuts::{CurrencyUnit, Token};
    use std::str::FromStr as _;

    let token = Token::from_str(token_text).context("invalid Cashu token")?;
    let mint_url = token
        .mint_url()
        .context("Cashu token must contain proofs from one mint")?
        .to_string();
    let unit = token.unit().unwrap_or_default();
    if unit != CurrencyUnit::Sat {
        return Err(anyhow!("Cashu token unit must be sat, got {unit}"));
    }
    let amount_sat = token
        .value()
        .context("invalid Cashu token amount")?
        .to_u64();
    let memo = token.memo().clone().unwrap_or_default();
    if token.token_secrets().is_empty() {
        return Err(anyhow!("Cashu token contains no proofs"));
    }

    Ok(PaidRouteWalletTokenPreview {
        mint_url,
        amount_sat,
        memo,
        state: "unchecked",
        status_text: "Mint will verify when redeemed".to_string(),
        redeemable: true,
    })
}
