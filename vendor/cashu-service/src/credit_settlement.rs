use crate::wallet::resume_transfer_between_mints;
use crate::{
    normalize_mint_url, transfer_between_mints, CashuCrossMintTransfer,
    CashuCrossMintTransferRequest,
};
use anyhow::{bail, Context, Result};
use cashu_credit::ExternalSettlementAuthorization;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// An application-approved mapping from one accounting issuer to its wallet mint.
///
/// Selection and trust policy stay with the caller. This adapter only proves that
/// the authorization and the executed CDK transfer use the selected route exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CashuIssuerRoute {
    pub issuer: String,
    pub source_mint_url: String,
}

/// Validate an external authorization and bind it to one exact CDK transfer.
pub fn prepare_cashu_settlement(
    authorization: &ExternalSettlementAuthorization,
    route: &CashuIssuerRoute,
    now_unix: u64,
) -> Result<CashuCrossMintTransferRequest> {
    let request = bind_cashu_settlement(authorization, route)?;
    if authorization.expires_at_unix <= now_unix {
        bail!("Cashu settlement authorization has expired");
    }
    Ok(request)
}

fn bind_cashu_settlement(
    authorization: &ExternalSettlementAuthorization,
    route: &CashuIssuerRoute,
) -> Result<CashuCrossMintTransferRequest> {
    if route.issuer != authorization.issuer {
        bail!("Cashu settlement route does not match the authorized issuer");
    }
    if authorization.settlement_id.trim() != authorization.settlement_id
        || authorization.settlement_id.is_empty()
        || authorization.issuer.trim().is_empty()
        || authorization.counterparty.trim().is_empty()
    {
        bail!("Cashu settlement authorization identity is not canonical");
    }
    if authorization.amount_sat == 0 {
        bail!("Cashu settlement amount must be greater than zero");
    }
    let reserved_sat = authorization
        .amount_sat
        .checked_add(authorization.max_fee_sat)
        .context("Cashu settlement reserve overflow")?;
    if authorization.reserved_sat != reserved_sat {
        bail!("Cashu settlement authorization has an invalid reserve");
    }
    if authorization.authorized_at_unix >= authorization.expires_at_unix {
        bail!("Cashu settlement authorization has an invalid deadline");
    }

    let source_mint_url = normalize_mint_url(&route.source_mint_url)
        .context("Cashu settlement source mint is invalid")?;
    let destination_mint_url = normalize_mint_url(&authorization.payout_destination)
        .context("Cashu settlement destination mint is invalid")?;
    if destination_mint_url != authorization.payout_destination {
        bail!("Cashu settlement destination mint must be canonical");
    }

    Ok(CashuCrossMintTransferRequest {
        transfer_id: authorization.settlement_id.clone(),
        source_mint_url,
        destination_mint_url,
        amount_sat: authorization.amount_sat,
        max_fee_sat: authorization.max_fee_sat,
    })
}

/// Execute or resume the liquidity-conversion leg of one authorized settlement.
///
/// Persist the authorization before calling this function. If the process stops
/// after payment but before account completion, retrying the same authorization
/// resumes the same transfer ID and returns the same result.
///
/// The destination proofs remain in this process's wallet. A mint URL alone does
/// not identify the counterparty, so this result is not evidence that they were
/// paid. The caller must durably deliver value under an authenticated application
/// protocol and journal `settlement_id -> exact bearer token -> authenticated
/// receiver ACK` before passing `fee_paid_sat` to
/// `CreditAccount::complete_external_settlement`.
/// Run only one wallet writer process per `data_dir`; the saga lock is process-local.
pub async fn execute_cashu_settlement(
    data_dir: &Path,
    authorization: &ExternalSettlementAuthorization,
    route: &CashuIssuerRoute,
    now_unix: u64,
) -> Result<CashuCrossMintTransfer> {
    let request = bind_cashu_settlement(authorization, route)?;
    let transfer = if authorization.expires_at_unix <= now_unix {
        // An expired authorization cannot start a payment. Recovery remains
        // necessary when an irrevocable payment began before the deadline.
        resume_transfer_between_mints(data_dir, request.clone()).await?
    } else {
        transfer_between_mints(data_dir, request.clone()).await?
    };
    if transfer.transfer_id != request.transfer_id
        || transfer.source_mint_url != request.source_mint_url
        || transfer.destination_mint_url != request.destination_mint_url
        || transfer.amount_sat != request.amount_sat
        || transfer.max_fee_sat != request.max_fee_sat
        || transfer.fee_paid_sat > request.max_fee_sat
        || transfer.unit != "sat"
    {
        bail!("CDK transfer result does not match the Cashu settlement authorization");
    }
    Ok(transfer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authorization() -> ExternalSettlementAuthorization {
        ExternalSettlementAuthorization {
            settlement_id: "settlement-1".to_string(),
            issuer: "alice".to_string(),
            counterparty: "bob".to_string(),
            payout_destination: "https://destination.example".to_string(),
            amount_sat: 21,
            max_fee_sat: 2,
            reserved_sat: 23,
            authorized_at_unix: 100,
            expires_at_unix: 200,
        }
    }

    fn route() -> CashuIssuerRoute {
        CashuIssuerRoute {
            issuer: "alice".to_string(),
            source_mint_url: "https://source.example/".to_string(),
        }
    }

    #[test]
    fn authorization_maps_to_one_exact_transfer() {
        let request = prepare_cashu_settlement(&authorization(), &route(), 150).unwrap();
        assert_eq!(request.transfer_id, "settlement-1");
        assert_eq!(request.source_mint_url, "https://source.example");
        assert_eq!(request.destination_mint_url, "https://destination.example");
        assert_eq!(request.amount_sat, 21);
        assert_eq!(request.max_fee_sat, 2);
    }

    #[test]
    fn authorization_rejects_route_redirect_reserve_and_expiry_changes() {
        let mut wrong_route = route();
        wrong_route.issuer = "mallory".to_string();
        assert!(prepare_cashu_settlement(&authorization(), &wrong_route, 150).is_err());

        let mut redirected = authorization();
        redirected.payout_destination = "https://DESTINATION.example/".to_string();
        assert!(prepare_cashu_settlement(&redirected, &route(), 150).is_err());

        let mut unreserved_fee = authorization();
        unreserved_fee.max_fee_sat = 3;
        assert!(prepare_cashu_settlement(&unreserved_fee, &route(), 150).is_err());

        assert!(prepare_cashu_settlement(&authorization(), &route(), 200).is_err());
    }
}
