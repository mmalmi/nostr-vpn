#![cfg(feature = "credit-settlement")]

use cashu_credit::ExternalSettlementAuthorization;
use cashu_service::{prepare_cashu_settlement, CashuIssuerRoute};

#[test]
fn public_adapter_binds_one_authorized_route_without_redirects() {
    let authorization = ExternalSettlementAuthorization {
        settlement_id: "verified-delivery-1".to_string(),
        issuer: "payer-mint".to_string(),
        counterparty: "provider".to_string(),
        payout_destination: "https://provider-mint.example".to_string(),
        amount_sat: 8,
        max_fee_sat: 1,
        reserved_sat: 9,
        authorized_at_unix: 100,
        expires_at_unix: 200,
    };
    let route = CashuIssuerRoute {
        issuer: "payer-mint".to_string(),
        source_mint_url: "https://payer-mint.example".to_string(),
    };

    let request = prepare_cashu_settlement(&authorization, &route, 150).unwrap();
    assert_eq!(request.transfer_id, authorization.settlement_id);
    assert_eq!(request.source_mint_url, route.source_mint_url);
    assert_eq!(
        request.destination_mint_url,
        authorization.payout_destination
    );
    assert_eq!(request.amount_sat, authorization.amount_sat);

    let mut redirected = authorization;
    redirected.payout_destination = "https://PROVIDER-MINT.example/".to_string();
    assert!(prepare_cashu_settlement(&redirected, &route, 150).is_err());
}
