use super::*;

// ============================================================================
// TEST/DEMO HELPERS
// ============================================================================
// These functions consolidate common patterns used across language bindings
// (Go, Python, TypeScript) in tests and demos.

/// Build a cashuA token string from proofs JSON and a mint URL.
///
/// Takes a JSON array of proofs and wraps them in the cashuA token format:
/// `"cashuA" + base64url({ token: [{ mint, proofs }], unit: "sat" })`
///
/// # Arguments
/// * `mint_url` - The mint URL to embed in the token
/// * `proofs_json` - JSON array of proofs (from construct_proofs or mint response)
///
/// # Returns
/// A cashuA token string (e.g. "cashuAeyJ0b2...")
pub fn build_cashu_a_token(mint_url: &str, proofs_json: &str) -> Result<String, String> {
    use cashu::mint_url::MintUrl;
    use cashu::nuts::nut00::TokenV3;

    let proofs: Vec<Proof> =
        serde_json::from_str(proofs_json).map_err(|e| format!("Failed to parse proofs: {}", e))?;

    let mint_url = MintUrl::from_str(mint_url).map_err(|e| format!("Invalid mint URL: {}", e))?;

    let token = TokenV3::new(mint_url, proofs, None, Some(CurrencyUnit::Sat))
        .map_err(|e| format!("Failed to create TokenV3: {}", e))?;

    Ok(token.to_string())
}

/// Build a cashuB (v4) token string from proofs JSON, a mint URL, and a unit.
///
/// Takes a JSON array of proofs and wraps them in the cashuB token format
/// (CBOR-encoded, `"cashuB" + base64url(...)`).
///
/// # Arguments
/// * `mint_url` - The mint URL to embed in the token
/// * `unit` - The currency unit (e.g. "sat", "msat", "usd")
/// * `proofs_json` - JSON array of proofs (must include witness fields if present)
///
/// # Returns
/// A cashuB token string (e.g. "cashuBpGF0...")
pub fn build_cashu_b_token(
    mint_url: &str,
    unit: &str,
    proofs_json: &str,
) -> Result<String, String> {
    use cashu::mint_url::MintUrl;

    let proofs: Vec<Proof> =
        serde_json::from_str(proofs_json).map_err(|e| format!("Failed to parse proofs: {}", e))?;

    let mint_url = MintUrl::from_str(mint_url).map_err(|e| format!("Invalid mint URL: {}", e))?;

    let currency_unit =
        CurrencyUnit::from_str(unit).unwrap_or_else(|_| CurrencyUnit::Custom(unit.into()));

    let token = Token::new(mint_url, proofs, None, currency_unit);

    Ok(token.to_string())
}

/// Mint plain proofs from a Cashu mint via HTTP.
///
/// Performs the full minting flow:
/// 1. Creates plain blinded messages for the given amount
/// 2. Requests a mint quote via POST /v1/mint/quote/bolt11
/// 3. Polls until the quote is PAID (up to 60 attempts, 100ms apart)
/// 4. Mints tokens via POST /v1/mint/bolt11
/// 5. Constructs and returns the proofs
///
/// The caller provides HTTP capabilities via the `call_http` callback:
/// - `call_http("POST", url, body_json)` -> response body as JSON string
/// - `call_http("GET", url, "")` -> response body as JSON string
///
/// This function is intended for tests and demos (especially with fakewallet
/// mints that auto-pay invoices).
///
/// # Arguments
/// * `mint_url` - The mint URL (e.g. "http://localhost:3338")
/// * `amount_sat` - Amount to mint in satoshis
/// * `keyset_info_json` - Keyset info JSON (from fetch_active_keyset)
/// * `call_http` - HTTP callback: (method, url, body) -> response_json
///
/// # Returns
/// JSON array of proofs ready for use
#[cfg(feature = "wallet")]
pub fn mint_proofs_from_mint(
    mint_url: &str,
    amount_sat: u64,
    keyset_info_json: &str,
    call_http: &dyn Fn(&str, &str, &str) -> Result<String, String>,
) -> Result<String, String> {
    // 1. Create plain blinded messages
    let result_json = create_plain_blinded_messages(amount_sat, keyset_info_json)?;
    let result: serde_json::Value = serde_json::from_str(&result_json)
        .map_err(|e| format!("Failed to parse blinded messages result: {}", e))?;
    let blinded_messages = &result["blinded_messages"];
    let secrets_with_blinding = result["secrets_with_blinding"].to_string();

    // 2. Request a mint quote
    let quote_body = serde_json::json!({
        "amount": amount_sat,
        "unit": "sat"
    })
    .to_string();

    let quote_url = format!("{}/v1/mint/quote/bolt11", mint_url);
    let quote_resp = call_http("POST", &quote_url, &quote_body)?;
    let quote: serde_json::Value = serde_json::from_str(&quote_resp)
        .map_err(|e| format!("Failed to parse mint quote response: {}", e))?;
    let quote_id = quote["quote"]
        .as_str()
        .ok_or("Missing 'quote' in mint quote response")?;

    // 3. Poll until paid (fakewallet auto-pays)
    let poll_url = format!("{}/v1/mint/quote/bolt11/{}", mint_url, quote_id);
    for i in 0..60 {
        let poll_resp = call_http("GET", &poll_url, "")?;
        let poll: serde_json::Value = serde_json::from_str(&poll_resp)
            .map_err(|e| format!("Failed to parse poll response: {}", e))?;
        if poll["state"].as_str() == Some("PAID") {
            break;
        }
        if i == 59 {
            return Err("Timeout waiting for mint quote to be paid".to_string());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // 4. Mint tokens
    let mint_body = serde_json::json!({
        "quote": quote_id,
        "outputs": blinded_messages
    })
    .to_string();

    let mint_token_url = format!("{}/v1/mint/bolt11", mint_url);
    let mint_resp = call_http("POST", &mint_token_url, &mint_body)?;
    let mint_result: serde_json::Value = serde_json::from_str(&mint_resp)
        .map_err(|e| format!("Failed to parse mint response: {}", e))?;
    let signatures = mint_result["signatures"]
        .as_array()
        .ok_or("Missing 'signatures' in mint response")?;
    let signatures_json = serde_json::to_string(signatures)
        .map_err(|e| format!("Failed to serialize signatures: {}", e))?;

    // 5. Construct proofs
    construct_proofs(&signatures_json, &secrets_with_blinding, keyset_info_json)
}
