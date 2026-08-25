use std::str::FromStr;
use std::sync::Arc;

use cashu_credit::{
    AcceptanceMode, AccountPolicy, BackingDeposit, CreditAccount, ExternalSettlementRequest,
    IssuerPolicy, ServiceReceiptClaim, ValueClass,
};
use cdk::cdk_payment::{
    Bolt11IncomingPaymentOptions, Bolt11OutgoingPaymentOptions, IncomingPaymentOptions,
    MintPayment, OutgoingPaymentOptions,
};
use cdk::mint_url::MintUrl;
use cdk::nuts::{CurrencyUnit, MeltOptions, MintQuoteState};
use cdk::Amount;

use super::*;
use crate::credit_settlement::{execute_cashu_settlement, CashuIssuerRoute};
use crate::{
    create_topup_quote, load_mint_balance, receive_payment_token, send_lightning_payment,
    send_payment_token, CashuWalletService, CreditAccountStore,
};

const START_TIME: u64 = 1_700_000_000;

fn test_network(fee_sat: u64) -> (Arc<VirtualClock>, PaymentNetwork) {
    let clock = Arc::new(VirtualClock::new(START_TIME));
    let network = PaymentNetwork::new(42, fee_sat, clock.clone());
    (clock, network)
}

async fn invoice(
    backend: &SimMintPayment,
    amount_sat: u64,
    expiry: u64,
) -> cdk::cdk_payment::CreateIncomingPaymentResponse {
    backend
        .create_incoming_payment_request(IncomingPaymentOptions::Bolt11(
            Bolt11IncomingPaymentOptions {
                description: Some("simulation test".to_string()),
                amount: Amount::new(amount_sat, CurrencyUnit::Sat),
                unix_expiry: Some(expiry),
            },
        ))
        .await
        .unwrap()
}

fn outgoing(
    payment_request: &str,
    max_fee_sat: Option<u64>,
    melt_options: Option<MeltOptions>,
) -> OutgoingPaymentOptions {
    OutgoingPaymentOptions::Bolt11(Box::new(Bolt11OutgoingPaymentOptions {
        bolt11: cdk::Bolt11Invoice::from_str(payment_request).unwrap(),
        max_fee_amount: max_fee_sat.map(|fee| Amount::new(fee, CurrencyUnit::Sat)),
        timeout_secs: None,
        melt_options,
        quote_id: cdk_common::QuoteId::default(),
    }))
}

#[tokio::test]
async fn invoice_stays_unpaid_until_one_atomic_authorized_payment() {
    let (_clock, network) = test_network(1);
    let funding = network.orchestrator_funding();
    let destination = network
        .payment_backend("destination", IssuerMode::ClosedLoop)
        .unwrap();
    let source = network
        .payment_backend("source", IssuerMode::Withdrawable)
        .unwrap();
    let quote = invoice(&destination, 25, START_TIME + 60).await;

    assert_eq!(
        network.invoice(&quote.request).unwrap().status,
        InvoiceStatus::Unpaid
    );
    assert!(destination
        .check_incoming_payment_status(&quote.request_lookup_id)
        .await
        .unwrap()
        .is_empty());

    let source_funding = invoice(&source, 26, START_TIME + 60).await;
    funding.settle_external(&source_funding.request).unwrap();
    let duplicate_funding = funding
        .settle_external(&source_funding.request)
        .unwrap_err();
    assert!(matches!(
        duplicate_funding,
        cdk::cdk_payment::Error::InvoiceAlreadyPaid
    ));
    let funded = network.accounting().unwrap();
    assert_eq!(funded.mint_reserve("source"), Some(26));
    assert_eq!(funded.external_funding_sat, 26);
    assert!(funded.is_conserved());

    let first_options = outgoing(&quote.request, Some(1), None);
    let second_options = first_options.clone();
    let (first, second) = tokio::join!(
        source.make_payment(&CurrencyUnit::Sat, first_options),
        source.make_payment(&CurrencyUnit::Sat, second_options)
    );
    let successes = usize::from(first.is_ok()) + usize::from(second.is_ok());
    let duplicate = [first, second]
        .into_iter()
        .filter_map(Result::err)
        .any(|error| matches!(error, cdk::cdk_payment::Error::InvoiceAlreadyPaid));

    assert_eq!(successes, 1);
    assert!(duplicate);
    assert_eq!(
        network.invoice(&quote.request).unwrap().status,
        InvoiceStatus::Paid
    );
    assert_eq!(
        destination
            .check_incoming_payment_status(&quote.request_lookup_id)
            .await
            .unwrap()
            .len(),
        1
    );
    let settled = network.accounting().unwrap();
    assert_eq!(settled.mint_reserve("source"), Some(0));
    assert_eq!(settled.mint_reserve("destination"), Some(25));
    assert_eq!(settled.total_reserve_sat, 25);
    assert_eq!(settled.fee_sink_sat, 1);
    assert_eq!(settled.total_accounted_sat, 26);
    assert_eq!(settled.external_funding_sat, 26);
    assert!(settled.is_conserved());
}

#[tokio::test]
async fn insufficient_liquidity_rejects_without_paying_or_minting_value() {
    let (_clock, network) = test_network(1);
    let destination = network
        .payment_backend("destination", IssuerMode::ClosedLoop)
        .unwrap();
    let source = network
        .payment_backend("source", IssuerMode::Withdrawable)
        .unwrap();
    let quote = invoice(&destination, 5, START_TIME + 60).await;

    let error = source
        .make_payment(&CurrencyUnit::Sat, outgoing(&quote.request, Some(1), None))
        .await
        .unwrap_err();

    assert!(error.to_string().contains("insufficient liquidity"));
    assert_eq!(
        network.invoice(&quote.request).unwrap().status,
        InvoiceStatus::Unpaid
    );
    let accounting = network.accounting().unwrap();
    assert_eq!(accounting.total_reserve_sat, 0);
    assert_eq!(accounting.fee_sink_sat, 0);
    assert_eq!(accounting.external_funding_sat, 0);
    assert!(accounting.is_conserved());
}

#[tokio::test]
async fn closed_loop_and_network_policy_rejections_are_enforced() {
    let (clock, network) = test_network(2);
    let funding = network.orchestrator_funding();
    let destination = network
        .payment_backend("destination", IssuerMode::ClosedLoop)
        .unwrap();
    let source = network
        .payment_backend("source", IssuerMode::Withdrawable)
        .unwrap();
    let quote = invoice(&destination, 10, START_TIME + 5).await;
    let source_funding = invoice(&source, 12, START_TIME + 60).await;
    funding.settle_external(&source_funding.request).unwrap();

    let closed_loop_error = destination
        .get_payment_quote(&CurrencyUnit::Sat, outgoing(&quote.request, Some(2), None))
        .await
        .unwrap_err();
    assert!(closed_loop_error
        .to_string()
        .contains("does not allow withdrawals"));

    let fee_error = source
        .make_payment(&CurrencyUnit::Sat, outgoing(&quote.request, Some(1), None))
        .await
        .unwrap_err();
    assert!(fee_error.to_string().contains("fee exceeds"));

    let amount_error = source
        .get_payment_quote(
            &CurrencyUnit::Sat,
            outgoing(
                &quote.request,
                Some(2),
                Some(MeltOptions::new_amountless(11_000_u64)),
            ),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        amount_error,
        cdk::cdk_payment::Error::AmountMismatch
    ));

    network.set_online("destination", false).unwrap();
    let outage_error = source
        .make_payment(&CurrencyUnit::Sat, outgoing(&quote.request, Some(2), None))
        .await
        .unwrap_err();
    assert!(outage_error
        .to_string()
        .contains("destination mint is offline"));
    network.set_online("destination", true).unwrap();

    clock.advance(5).unwrap();
    let expiry_error = source
        .make_payment(&CurrencyUnit::Sat, outgoing(&quote.request, Some(2), None))
        .await
        .unwrap_err();
    assert!(expiry_error.to_string().contains("invoice expired"));
    assert_eq!(
        network.invoice(&quote.request).unwrap().status,
        InvoiceStatus::Unpaid
    );
    let rejected = network.accounting().unwrap();
    assert_eq!(rejected.mint_reserve("source"), Some(12));
    assert_eq!(rejected.mint_reserve("destination"), Some(0));
    assert_eq!(rejected.fee_sink_sat, 0);
    assert!(rejected.is_conserved());

    let overflow_network = PaymentNetwork::new(43, u64::MAX, clock);
    let overflow_destination = overflow_network
        .payment_backend("overflow-destination", IssuerMode::ClosedLoop)
        .unwrap();
    let overflow_source = overflow_network
        .payment_backend("overflow-source", IssuerMode::Withdrawable)
        .unwrap();
    let overflow_quote = invoice(&overflow_destination, 1, START_TIME + 60).await;
    let overflow = overflow_source
        .make_payment(
            &CurrencyUnit::Sat,
            outgoing(&overflow_quote.request, None, None),
        )
        .await
        .unwrap_err();
    assert!(matches!(overflow, cdk::cdk_payment::Error::AmountMismatch));
    assert_eq!(
        overflow_network
            .invoice(&overflow_quote.request)
            .unwrap()
            .status,
        InvoiceStatus::Unpaid
    );
}

#[tokio::test]
async fn local_mints_use_unique_deterministic_keysets_and_sqlite() {
    let temp = tempfile::tempdir().unwrap();
    let (_clock, network) = test_network(1);
    let first = LocalMint::start(
        temp.path(),
        network.clone(),
        "mint-a",
        IssuerMode::Withdrawable,
    )
    .await
    .unwrap();
    let second = LocalMint::start(temp.path(), network, "mint-b", IssuerMode::ClosedLoop)
        .await
        .unwrap();

    assert_ne!(first.active_sat_keyset(), second.active_sat_keyset());
    assert!(first.database_path().is_file());
    assert!(second.database_path().is_file());
    assert_ne!(first.database_path(), second.database_path());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closed_loop_mint_accepts_real_swaps_and_rejects_online_double_spend() {
    let temp = tempfile::tempdir().unwrap();
    let sender_dir = temp.path().join("sender");
    let first_receiver_dir = temp.path().join("receiver-1");
    let second_receiver_dir = temp.path().join("receiver-2");
    let (_clock, network) = test_network(1);
    let funding = network.orchestrator_funding();
    let mint = LocalMint::start(
        temp.path(),
        network.clone(),
        "closed-loop",
        IssuerMode::ClosedLoop,
    )
    .await
    .unwrap();
    fund_source_wallet(&sender_dir, &mint, &network, &funding, 16).await;

    let payment = send_payment_token(&sender_dir, mint.url(), 8)
        .await
        .unwrap();
    let received = receive_payment_token(&first_receiver_dir, &payment.token)
        .await
        .unwrap();
    let replay = receive_payment_token(&second_receiver_dir, &payment.token)
        .await
        .unwrap_err();

    assert_eq!(received.amount_sat, 8);
    assert!(replay
        .to_string()
        .contains("Failed to receive Cashu payment token"));
    assert_eq!(
        load_mint_balance(&first_receiver_dir, mint.url())
            .await
            .unwrap()
            .balance_sat,
        8
    );
    assert_eq!(
        load_mint_balance(&sender_dir, mint.url())
            .await
            .unwrap()
            .balance_sat,
        8
    );
    assert_eq!(
        load_mint_balance(&second_receiver_dir, mint.url())
            .await
            .unwrap()
            .balance_sat,
        0
    );
    let accounting = network.accounting().unwrap();
    assert_eq!(accounting.mint_reserve("closed-loop"), Some(16));
    assert_eq!(accounting.fee_sink_sat, 0);
    assert!(accounting.is_conserved());
}

async fn fund_source_wallet(
    data_dir: &std::path::Path,
    source: &LocalMint,
    network: &PaymentNetwork,
    funding: &OrchestratorFunding,
    amount_sat: u64,
) {
    let quote = create_topup_quote(data_dir, source.url(), amount_sat)
        .await
        .unwrap();
    assert_eq!(
        network.invoice(&quote.payment_request).unwrap().status,
        InvoiceStatus::Unpaid
    );
    funding.settle_external(&quote.payment_request).unwrap();

    let service = CashuWalletService::open_file_backed(data_dir)
        .await
        .unwrap();
    let mint_url = MintUrl::from_str(source.url()).unwrap();
    let wallet = service
        .repository()
        .get_wallet(&mint_url, &CurrencyUnit::Sat)
        .await
        .unwrap();
    let status = wallet
        .check_mint_quote_status(&quote.quote_id)
        .await
        .unwrap();
    assert_eq!(status.state, MintQuoteState::Paid);
    wallet
        .mint(&quote.quote_id, cdk::amount::SplitTarget::default(), None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn production_helper_transfers_real_cdk_proofs_between_isolated_mints() {
    let temp = tempfile::tempdir().unwrap();
    let wallet_dir = temp.path().join("wallet");
    let provider_dir = temp.path().join("provider");
    let (_clock, network) = test_network(1);
    let funding = network.orchestrator_funding();
    let source = LocalMint::start(
        temp.path(),
        network.clone(),
        "source",
        IssuerMode::Withdrawable,
    )
    .await
    .unwrap();
    let destination = LocalMint::start(
        temp.path(),
        network.clone(),
        "destination",
        IssuerMode::ClosedLoop,
    )
    .await
    .unwrap();
    fund_source_wallet(&wallet_dir, &source, &network, &funding, 64).await;
    let funded = network.accounting().unwrap();
    assert_eq!(funded.mint_reserve("source"), Some(64));
    assert_eq!(funded.mint_reserve("destination"), Some(0));
    assert_eq!(funded.total_reserve_sat, 64);
    assert_eq!(funded.external_funding_sat, 64);
    assert!(funded.is_conserved());

    let issuer = source.url().to_string();
    let mut account = CreditAccount::new(AccountPolicy {
        counterparty: "provider".to_string(),
        max_total_peer_credit_sat: 0,
        issuers: vec![IssuerPolicy {
            issuer: issuer.clone(),
            max_peer_credit_sat: 0,
            max_offline_peer_credit_sat: 0,
            max_closed_loop_sat: 0,
            max_withdrawable_sat: 64,
            expires_at_unix: Some(START_TIME + 60),
        }],
    })
    .unwrap();
    account
        .record_backing_deposit(
            &BackingDeposit {
                deposit_id: "source-funding".to_string(),
                issuer: issuer.clone(),
                amount_sat: 64,
                value_class: ValueClass::ReserveBackedWithdrawable,
            },
            &issuer,
        )
        .unwrap();
    account
        .apply_receipt(
            &ServiceReceiptClaim {
                receipt_id: "verified-service".to_string(),
                issuer: issuer.clone(),
                counterparty: "provider".to_string(),
                service: "verified_delivery".to_string(),
                resource: "pubsub:subscription:author".to_string(),
                useful_service_units: 32_768,
                amount_sat: 33,
                value_class: ValueClass::ReserveBackedWithdrawable,
                issued_at_unix: START_TIME,
                expires_at_unix: START_TIME + 60,
            },
            &issuer,
            AcceptanceMode::Online,
            START_TIME,
        )
        .unwrap();
    let authorization = account
        .authorize_external_settlement(
            &ExternalSettlementRequest {
                settlement_id: "real-cdk-transfer".to_string(),
                issuer: issuer.clone(),
                counterparty: "provider".to_string(),
                payout_destination: destination.url().to_string(),
                amount_sat: 32,
                max_fee_sat: 1,
                expires_at_unix: START_TIME + 60,
            },
            "provider",
            START_TIME,
        )
        .unwrap();
    let account_revision = account.revision();
    let mut store = CreditAccountStore::open(temp.path().join("credit.sqlite3")).unwrap();
    store.create("provider", &account).unwrap();
    let route = CashuIssuerRoute {
        issuer,
        source_mint_url: source.url().to_string(),
    };

    let transfer = execute_cashu_settlement(&wallet_dir, &authorization, &route, START_TIME)
        .await
        .unwrap();
    let paid_once = network.accounting().unwrap();

    // Cross-mint execution converts liquidity into the payer's destination
    // wallet. Settlement is complete only after the provider receives value.
    let payout = send_payment_token(&wallet_dir, destination.url(), 32)
        .await
        .unwrap();
    assert_eq!(payout.send_fee_sat, 0);
    let provider_payment = receive_payment_token(&provider_dir, &payout.token)
        .await
        .unwrap();
    assert_eq!(provider_payment.amount_sat, 32);
    assert_eq!(network.accounting().unwrap(), paid_once);

    // Simulate a crash before account completion. The durable authorization is
    // still pending, and replay resumes the same CDK transfer without paying twice.
    drop(account);
    let replay = execute_cashu_settlement(&wallet_dir, &authorization, &route, START_TIME + 61)
        .await
        .unwrap();
    assert_eq!(replay, transfer);
    assert_eq!(network.accounting().unwrap(), paid_once);

    let mut recovered = store.load("provider").unwrap().unwrap();
    assert_eq!(recovered.revision(), account_revision);
    recovered
        .complete_external_settlement(&authorization.settlement_id, transfer.fee_paid_sat)
        .unwrap();
    store
        .save("provider", account_revision, &recovered)
        .unwrap();
    let persisted = store.load("provider").unwrap().unwrap();
    let reserve = persisted.sat_reserve(source.url()).unwrap();
    assert_eq!(reserve.total_deposited_sat(), 64);
    assert_eq!(reserve.available_sat(), 31);
    assert_eq!(reserve.pending_external_sat(), 0);
    assert_eq!(reserve.settled_external_sat(), 33);
    assert_eq!(reserve.conserved_sat().unwrap(), 64);

    assert_eq!(transfer.amount_sat, 32);
    assert_eq!(transfer.fee_paid_sat, 1);
    assert_eq!(transfer.destination_balance_before_sat, 0);
    assert_eq!(transfer.destination_balance_after_sat, 32);
    assert_eq!(
        load_mint_balance(&wallet_dir, destination.url())
            .await
            .unwrap()
            .balance_sat,
        0
    );
    assert_eq!(
        load_mint_balance(&provider_dir, destination.url())
            .await
            .unwrap()
            .balance_sat,
        32
    );
    assert_eq!(
        load_mint_balance(&wallet_dir, source.url())
            .await
            .unwrap()
            .balance_sat,
        31
    );
    let transferred = network.accounting().unwrap();
    assert_eq!(transferred.mint_reserve("source"), Some(31));
    assert_eq!(transferred.mint_reserve("destination"), Some(32));
    assert_eq!(transferred.total_reserve_sat, 63);
    assert_eq!(transferred.fee_sink_sat, 1);
    assert_eq!(transferred.total_accounted_sat, 64);
    assert_eq!(transferred.external_funding_sat, 64);
    assert!(transferred.is_conserved());

    let withdrawal_invoice = invoice(source.payment(), 8, START_TIME + 60).await;
    let withdrawal_error =
        send_lightning_payment(&wallet_dir, destination.url(), &withdrawal_invoice.request)
            .await
            .unwrap_err();
    assert!(withdrawal_error.to_string().contains("melt quote"));
    assert_eq!(
        network.invoice(&withdrawal_invoice.request).unwrap().status,
        InvoiceStatus::Unpaid
    );
    assert_eq!(network.accounting().unwrap(), transferred);
}
