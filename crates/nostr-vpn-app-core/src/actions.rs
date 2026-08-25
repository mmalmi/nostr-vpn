use serde::{Deserialize, Serialize};

use crate::state::SettingsPatch;

#[derive(uniffi::Enum, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum NativeAppAction {
    GetState,
    Tick,
    ConnectVpn,
    DisconnectVpn,
    InstallCli,
    UninstallCli,
    InstallSystemService,
    UninstallSystemService,
    EnableSystemService,
    DisableSystemService,
    AddNetwork {
        name: String,
    },
    RenameNetwork {
        network_id: String,
        name: String,
    },
    RemoveNetwork {
        network_id: String,
    },
    SetNetworkMeshId {
        network_id: String,
        mesh_id: String,
    },
    SetNetworkEnabled {
        network_id: String,
        enabled: bool,
    },
    SetNetworkJoinRequestsEnabled {
        network_id: String,
        enabled: bool,
    },
    AddParticipant {
        network_id: String,
        npub: String,
        alias: Option<String>,
    },
    AddAdmin {
        network_id: String,
        npub: String,
    },
    #[serde(alias = "import_join_request_qr_or_link")]
    ImportJoinRequest {
        request: String,
    },
    /// Explicit out-of-band join: trust an admin Device ID and Network ID
    /// entered by the user. The admin must add this device's ID on their side.
    ManualAddNetwork {
        admin_npub: String,
        mesh_network_id: String,
    },
    RemoveParticipant {
        network_id: String,
        npub: String,
    },
    RemoveAdmin {
        network_id: String,
        npub: String,
    },
    AcceptJoinRequest {
        network_id: String,
        requester_npub: String,
    },
    RejectJoinRequest {
        network_id: String,
        requester_npub: String,
    },
    SetParticipantAlias {
        npub: String,
        alias: String,
    },
    SetParticipantEndpointHints {
        npub: String,
        endpoint_hints: Vec<String>,
    },
    AddPaidRouteWalletMint {
        url: String,
        label: Option<String>,
    },
    RemovePaidRouteWalletMint {
        url: String,
    },
    SetPaidRouteDefaultMint {
        url: String,
    },
    RefreshPaidRouteWallet {
        refresh: bool,
    },
    TopUpPaidRouteWallet {
        mint_url: Option<String>,
        amount_sat: u64,
    },
    ReceivePaidRouteWalletToken {
        token: String,
    },
    PreviewPaidRouteWalletToken {
        token: String,
    },
    SendPaidRouteWalletToken {
        mint_url: Option<String>,
        amount_sat: u64,
    },
    WithdrawPaidRouteWalletLightning {
        mint_url: Option<String>,
        invoice: String,
    },
    BuyPaidRouteOffer {
        offer_key: String,
        mint_url: Option<String>,
        channel_capacity_sat: Option<u64>,
    },
    BuyBestPaidRouteOffer {
        mint_url: Option<String>,
        channel_capacity_sat: Option<u64>,
    },
    SetManualPaidExitProvider {
        provider: String,
    },
    ClearManualPaidExitProvider,
    SelectPaidRouteSession {
        session_id: String,
        connect: bool,
    },
    ProbePaidRouteSession {
        session_id: String,
        timeout_secs: u64,
    },
    RecordPaidRouteProbe {
        session_id: String,
        realized_exit_ip: Option<String>,
        observed_country_code: Option<String>,
        observed_asn: Option<u32>,
        latency_ms: Option<u32>,
        jitter_ms: Option<u32>,
        packet_loss_ppm: Option<u32>,
        down_bps: Option<u64>,
        up_bps: Option<u64>,
        uptime_secs: Option<u64>,
        last_seen_unix: Option<u64>,
    },
    CreatePaidRoutePaymentEnvelope {
        session_id: String,
        kind: String,
        payment_json: String,
        delivered_units: Option<u64>,
        paid_msat: Option<u64>,
    },
    OpenPaidRouteChannelFromWallet {
        session_id: String,
        mint_url: Option<String>,
        paid_msat: Option<u64>,
        max_amount_per_output: Option<u64>,
        keyset_id: Option<String>,
    },
    SignPaidRoutePaymentEnvelopeFromWallet {
        session_id: String,
        kind: String,
        delivered_units: Option<u64>,
        paid_msat: Option<u64>,
    },
    ClosePaidRouteChannelFromWallet {
        session_id: String,
        publish: bool,
    },
    ApplyPaidRoutePaymentEnvelope {
        envelope_json: String,
    },
    SendPaidRoutePaymentEnvelope {
        envelope_json: String,
    },
    StreamPaidRoutePayments {
        publish: bool,
        min_increment_msat: u64,
        limit: u64,
    },
    ClearPaidRouteActivity,
    ReceivePaidRoutePayments {
        duration_secs: u64,
    },
    CollectPaidExitChannel {
        channel_id: String,
    },
    CollectDuePaidExitChannels,
    PublishPaidExitOffer,
    SetPaidRouteMarketFilter {
        query: String,
        country_code: String,
        mint_url: String,
        require_ipv4: bool,
        require_ipv6: bool,
        sort: String,
    },
    DiscoverPaidRouteOffers {
        duration_secs: u64,
    },
    UpdateSettings {
        patch: SettingsPatch,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_action_json_roundtrip(action: &NativeAppAction, expected: &str) {
        let encoded = serde_json::to_string(action).expect("serialize action");
        assert_eq!(encoded, expected);
        assert_eq!(
            &serde_json::from_str::<NativeAppAction>(&encoded).expect("parse action"),
            action
        );
    }

    #[test]
    fn action_json_uses_current_names() {
        assert_eq!(
            serde_json::to_string(&NativeAppAction::ConnectVpn).expect("serialize action"),
            r#"{"type":"connect_vpn"}"#
        );

        let action = NativeAppAction::SetNetworkEnabled {
            network_id: "net-1".to_string(),
            enabled: true,
        };

        let encoded = serde_json::to_string(&action).expect("serialize action");
        assert_eq!(
            encoded,
            r#"{"type":"set_network_enabled","networkId":"net-1","enabled":true}"#
        );
        assert_eq!(
            serde_json::from_str::<NativeAppAction>(&encoded).expect("parse action"),
            action
        );
    }

    #[test]
    fn participant_endpoint_hint_action_uses_camel_case_field() {
        let action = NativeAppAction::SetParticipantEndpointHints {
            npub: "npub1peer".to_string(),
            endpoint_hints: vec!["peer.example.com:51820".to_string()],
        };

        let encoded = serde_json::to_string(&action).expect("serialize action");
        assert_eq!(
            encoded,
            r#"{"type":"set_participant_endpoint_hints","npub":"npub1peer","endpointHints":["peer.example.com:51820"]}"#
        );
        assert_eq!(
            serde_json::from_str::<NativeAppAction>(&encoded).expect("parse action"),
            action
        );
    }

    #[test]
    fn paid_route_wallet_actions_use_camel_case_fields() {
        let action = NativeAppAction::AddPaidRouteWalletMint {
            url: "https://mint.minibits.cash/Bitcoin".to_string(),
            label: Some("Minibits".to_string()),
        };

        let encoded = serde_json::to_string(&action).expect("serialize action");
        assert_eq!(
            encoded,
            r#"{"type":"add_paid_route_wallet_mint","url":"https://mint.minibits.cash/Bitcoin","label":"Minibits"}"#
        );
        assert_eq!(
            serde_json::from_str::<NativeAppAction>(&encoded).expect("parse action"),
            action
        );
    }

    #[test]
    fn import_join_request_action_alias_accepts_legacy_name() {
        let import = serde_json::from_str::<NativeAppAction>(
            r#"{"type":"import_join_request_qr_or_link","request":"nvpn://join-request/payload"}"#,
        )
        .expect("parse import join request alias");
        assert_eq!(
            import,
            NativeAppAction::ImportJoinRequest {
                request: "nvpn://join-request/payload".to_string(),
            }
        );
    }

    #[test]
    fn manual_join_action_uses_cross_platform_camel_case_fields() {
        let action = NativeAppAction::ManualAddNetwork {
            admin_npub: "npub1admin".to_string(),
            mesh_network_id: "8d4f34f5425bc50e".to_string(),
        };
        let encoded = serde_json::to_string(&action).expect("serialize action");
        assert_eq!(
            encoded,
            r#"{"type":"manual_add_network","adminNpub":"npub1admin","meshNetworkId":"8d4f34f5425bc50e"}"#
        );
        assert_eq!(
            serde_json::from_str::<NativeAppAction>(&encoded).expect("parse action"),
            action
        );
    }

    #[test]
    fn paid_route_buy_action_uses_camel_case_fields() {
        let action = NativeAppAction::BuyPaidRouteOffer {
            offer_key: "seller:internet-exit".to_string(),
            mint_url: Some("https://mint.minibits.cash/Bitcoin".to_string()),
            channel_capacity_sat: Some(100),
        };

        let encoded = serde_json::to_string(&action).expect("serialize action");
        assert_eq!(
            encoded,
            r#"{"type":"buy_paid_route_offer","offerKey":"seller:internet-exit","mintUrl":"https://mint.minibits.cash/Bitcoin","channelCapacitySat":100}"#
        );
        assert_eq!(
            serde_json::from_str::<NativeAppAction>(&encoded).expect("parse action"),
            action
        );

        let best = NativeAppAction::BuyBestPaidRouteOffer {
            mint_url: Some("https://mint.minibits.cash/Bitcoin".to_string()),
            channel_capacity_sat: Some(100),
        };
        let encoded = serde_json::to_string(&best).expect("serialize best buy");
        assert_eq!(
            encoded,
            r#"{"type":"buy_best_paid_route_offer","mintUrl":"https://mint.minibits.cash/Bitcoin","channelCapacitySat":100}"#
        );
        assert_eq!(
            serde_json::from_str::<NativeAppAction>(&encoded).expect("parse best buy"),
            best
        );

        let select = NativeAppAction::SelectPaidRouteSession {
            session_id: "session-1".to_string(),
            connect: true,
        };
        let encoded = serde_json::to_string(&select).expect("serialize select");
        assert_eq!(
            encoded,
            r#"{"type":"select_paid_route_session","sessionId":"session-1","connect":true}"#
        );
        assert_eq!(
            serde_json::from_str::<NativeAppAction>(&encoded).expect("parse select"),
            select
        );
    }

    #[test]
    fn paid_route_probe_action_uses_camel_case_fields() {
        let probe = NativeAppAction::ProbePaidRouteSession {
            session_id: "session-1".to_string(),
            timeout_secs: 5,
        };
        let encoded = serde_json::to_string(&probe).expect("serialize action");
        assert_eq!(
            encoded,
            r#"{"type":"probe_paid_route_session","sessionId":"session-1","timeoutSecs":5}"#
        );
        assert_eq!(
            serde_json::from_str::<NativeAppAction>(&encoded).expect("parse action"),
            probe
        );

        let action = NativeAppAction::RecordPaidRouteProbe {
            session_id: "session-1".to_string(),
            realized_exit_ip: Some("198.51.100.42".to_string()),
            observed_country_code: Some("FI".to_string()),
            observed_asn: Some(14_593),
            latency_ms: Some(42),
            jitter_ms: Some(7),
            packet_loss_ppm: Some(500),
            down_bps: Some(10_000_000),
            up_bps: Some(1_000_000),
            uptime_secs: Some(3600),
            last_seen_unix: Some(123),
        };

        let encoded = serde_json::to_string(&action).expect("serialize action");
        assert_eq!(
            encoded,
            r#"{"type":"record_paid_route_probe","sessionId":"session-1","realizedExitIp":"198.51.100.42","observedCountryCode":"FI","observedAsn":14593,"latencyMs":42,"jitterMs":7,"packetLossPpm":500,"downBps":10000000,"upBps":1000000,"uptimeSecs":3600,"lastSeenUnix":123}"#
        );
        assert_eq!(
            serde_json::from_str::<NativeAppAction>(&encoded).expect("parse action"),
            action
        );
    }

    #[test]
    fn paid_route_real_wallet_actions_use_camel_case_fields() {
        let top_up = NativeAppAction::TopUpPaidRouteWallet {
            mint_url: Some("https://mint.minibits.cash/Bitcoin".to_string()),
            amount_sat: 21,
        };
        let encoded = serde_json::to_string(&top_up).expect("serialize top-up");
        assert_eq!(
            encoded,
            r#"{"type":"top_up_paid_route_wallet","mintUrl":"https://mint.minibits.cash/Bitcoin","amountSat":21}"#
        );
        assert_eq!(
            serde_json::from_str::<NativeAppAction>(&encoded).expect("parse top-up"),
            top_up
        );

        let receive = NativeAppAction::ReceivePaidRouteWalletToken {
            token: "cashuAexample".to_string(),
        };
        assert_eq!(
            serde_json::to_string(&receive).expect("serialize receive"),
            r#"{"type":"receive_paid_route_wallet_token","token":"cashuAexample"}"#
        );

        let preview = NativeAppAction::PreviewPaidRouteWalletToken {
            token: "cashuAexample".to_string(),
        };
        assert_eq!(
            serde_json::to_string(&preview).expect("serialize preview"),
            r#"{"type":"preview_paid_route_wallet_token","token":"cashuAexample"}"#
        );

        let send = NativeAppAction::SendPaidRouteWalletToken {
            mint_url: None,
            amount_sat: 7,
        };
        assert_eq!(
            serde_json::to_string(&send).expect("serialize send"),
            r#"{"type":"send_paid_route_wallet_token","mintUrl":null,"amountSat":7}"#
        );

        let withdraw = NativeAppAction::WithdrawPaidRouteWalletLightning {
            mint_url: None,
            invoice: "lnbc1test".to_string(),
        };
        assert_eq!(
            serde_json::to_string(&withdraw).expect("serialize withdraw"),
            r#"{"type":"withdraw_paid_route_wallet_lightning","mintUrl":null,"invoice":"lnbc1test"}"#
        );

        let refresh = NativeAppAction::RefreshPaidRouteWallet { refresh: true };
        assert_eq!(
            serde_json::to_string(&refresh).expect("serialize refresh"),
            r#"{"type":"refresh_paid_route_wallet","refresh":true}"#
        );
    }

    #[test]
    fn paid_route_relay_actions_use_camel_case_fields() {
        assert_eq!(
            serde_json::to_string(&NativeAppAction::PublishPaidExitOffer)
                .expect("serialize action"),
            r#"{"type":"publish_paid_exit_offer"}"#
        );

        let filter = NativeAppAction::SetPaidRouteMarketFilter {
            query: "fiber".to_string(),
            country_code: "FI".to_string(),
            mint_url: "https://mint.example".to_string(),
            require_ipv4: true,
            require_ipv6: false,
            sort: "price".to_string(),
        };
        let encoded = serde_json::to_string(&filter).expect("serialize filter");
        assert_eq!(
            encoded,
            r#"{"type":"set_paid_route_market_filter","query":"fiber","countryCode":"FI","mintUrl":"https://mint.example","requireIpv4":true,"requireIpv6":false,"sort":"price"}"#
        );
        assert_eq!(
            serde_json::from_str::<NativeAppAction>(&encoded).expect("parse filter"),
            filter
        );

        let action = NativeAppAction::DiscoverPaidRouteOffers { duration_secs: 5 };
        let encoded = serde_json::to_string(&action).expect("serialize action");
        assert_eq!(
            encoded,
            r#"{"type":"discover_paid_route_offers","durationSecs":5}"#
        );
        assert_eq!(
            serde_json::from_str::<NativeAppAction>(&encoded).expect("parse action"),
            action
        );
    }

    #[test]
    fn paid_route_payment_actions_use_camel_case_fields() {
        let create = NativeAppAction::CreatePaidRoutePaymentEnvelope {
            session_id: "session-1".to_string(),
            kind: "balance_update".to_string(),
            payment_json: r#"{"channel_id":"channel-1"}"#.to_string(),
            delivered_units: Some(100),
            paid_msat: Some(1_000),
        };
        assert_action_json_roundtrip(
            &create,
            r#"{"type":"create_paid_route_payment_envelope","sessionId":"session-1","kind":"balance_update","paymentJson":"{\"channel_id\":\"channel-1\"}","deliveredUnits":100,"paidMsat":1000}"#,
        );

        let open = NativeAppAction::OpenPaidRouteChannelFromWallet {
            session_id: "session-1".to_string(),
            mint_url: Some("https://mint.minibits.cash/Bitcoin".to_string()),
            paid_msat: Some(1_000),
            max_amount_per_output: Some(64),
            keyset_id: Some("00abcd".to_string()),
        };
        assert_action_json_roundtrip(
            &open,
            r#"{"type":"open_paid_route_channel_from_wallet","sessionId":"session-1","mintUrl":"https://mint.minibits.cash/Bitcoin","paidMsat":1000,"maxAmountPerOutput":64,"keysetId":"00abcd"}"#,
        );

        let sign = NativeAppAction::SignPaidRoutePaymentEnvelopeFromWallet {
            session_id: "session-1".to_string(),
            kind: "balance-update".to_string(),
            delivered_units: Some(200),
            paid_msat: Some(2_000),
        };
        assert_action_json_roundtrip(
            &sign,
            r#"{"type":"sign_paid_route_payment_envelope_from_wallet","sessionId":"session-1","kind":"balance-update","deliveredUnits":200,"paidMsat":2000}"#,
        );

        let close = NativeAppAction::ClosePaidRouteChannelFromWallet {
            session_id: "session-1".to_string(),
            publish: true,
        };
        assert_action_json_roundtrip(
            &close,
            r#"{"type":"close_paid_route_channel_from_wallet","sessionId":"session-1","publish":true}"#,
        );

        let apply = NativeAppAction::ApplyPaidRoutePaymentEnvelope {
            envelope_json: r#"{"lease_id":"lease-1"}"#.to_string(),
        };
        assert_action_json_roundtrip(
            &apply,
            r#"{"type":"apply_paid_route_payment_envelope","envelopeJson":"{\"lease_id\":\"lease-1\"}"}"#,
        );

        let send = NativeAppAction::SendPaidRoutePaymentEnvelope {
            envelope_json: r#"{"lease_id":"lease-1"}"#.to_string(),
        };
        assert_action_json_roundtrip(
            &send,
            r#"{"type":"send_paid_route_payment_envelope","envelopeJson":"{\"lease_id\":\"lease-1\"}"}"#,
        );

        let stream = NativeAppAction::StreamPaidRoutePayments {
            publish: true,
            min_increment_msat: 100,
            limit: 5,
        };
        assert_action_json_roundtrip(
            &stream,
            r#"{"type":"stream_paid_route_payments","publish":true,"minIncrementMsat":100,"limit":5}"#,
        );

        let receive = NativeAppAction::ReceivePaidRoutePayments { duration_secs: 5 };
        assert_action_json_roundtrip(
            &receive,
            r#"{"type":"receive_paid_route_payments","durationSecs":5}"#,
        );

        let collect = NativeAppAction::CollectPaidExitChannel {
            channel_id: "channel-1".to_string(),
        };
        assert_action_json_roundtrip(
            &collect,
            r#"{"type":"collect_paid_exit_channel","channelId":"channel-1"}"#,
        );

        assert_action_json_roundtrip(
            &NativeAppAction::CollectDuePaidExitChannels,
            r#"{"type":"collect_due_paid_exit_channels"}"#,
        );
    }

    #[test]
    fn update_settings_action_round_trips() {
        let encoded = r#"{"type":"update_settings","patch":{"nodeName":"office","listenPort":51821,"relays":["wss://relay.example"],"exitNodeLeakProtection":true,"advertiseExitNode":true,"wireguardExitEnabled":true,"wireguardExitEndpoint":"198.51.100.20:51830","wireguardExitConfig":"[Interface]\nPrivateKey = client\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = peer\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.test:51820"}}"#;

        let action = serde_json::from_str::<NativeAppAction>(encoded).expect("parse action");
        match action {
            NativeAppAction::UpdateSettings { patch } => {
                assert_eq!(patch.node_name.as_deref(), Some("office"));
                assert_eq!(patch.listen_port, Some(51821));
                assert_eq!(patch.relays, Some(vec!["wss://relay.example".to_string()]));
                assert_eq!(patch.exit_node_leak_protection, Some(true));
                assert_eq!(patch.advertise_exit_node, Some(true));
                assert_eq!(patch.wireguard_exit_enabled, Some(true));
                assert_eq!(
                    patch.wireguard_exit_endpoint.as_deref(),
                    Some("198.51.100.20:51830")
                );
                assert!(
                    patch
                        .wireguard_exit_config
                        .as_deref()
                        .is_some_and(|config| config.contains("[Interface]"))
                );
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }
}
