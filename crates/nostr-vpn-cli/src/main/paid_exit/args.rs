#[derive(Debug, Args)]
struct PaidExitArgs {
    #[command(subcommand)]
    command: PaidExitCommand,
}

const DEFAULT_PAID_EXIT_RATING_SCOPE: &str = "vpn.exit";
const RATING_FACT_KIND: u64 = 7368;
#[cfg(test)]
const RATING_FACT_TYPE: &str = "rating";
#[cfg(test)]
const RATING_FACT_SCHEMA: &str = "1";
#[cfg(test)]
const PAID_EXIT_RATING_EVENT_LOOKUP_LIMIT: usize = 500;
const PAID_EXIT_OFFER_EVENT_CACHE_LIMIT: usize = 512;

#[derive(Debug, Subcommand)]
enum PaidExitCommand {
    /// Show paid-exit seller config, wallet, offers, channels, and sessions.
    Status(PaidExitStatusArgs),
    /// Rate a previously used provider; down stops and avoids it. Ratings publish automatically.
    Rate(PaidExitRateArgs),
    /// Ask Automatic mode to try another eligible provider without casting a vote.
    Reselect(PaidExitStatusArgs),
    /// Enable this machine as a paid-exit seller, refresh its offer, and optionally publish it.
    Run(PaidExitRunArgs),
    /// Build/sign the local paid-exit offer, and optionally publish it.
    Offer(PaidExitOfferArgs),
    /// Import a signed paid-exit offer event from JSON.
    #[command(name = "import-offer")]
    ImportOffer(PaidExitImportOfferArgs),
    /// Discover and verify paid-exit offers received over Nostr pubsub.
    Discover(PaidExitDiscoverArgs),
    /// Open a local buyer session for a discovered paid-exit offer.
    Buy(PaidExitBuyArgs),
    /// Select an existing buyer session as the active public exit route.
    Use(PaidExitUseArgs),
    /// Measure the realized public exit IP and quality for a paid-exit session.
    Probe(PaidExitProbeArgs),
    /// Record realized exit IP and quality measurements for a paid-exit session.
    #[command(name = "record-probe")]
    RecordProbe(PaidExitRecordProbeArgs),
    /// Export or publish machine-generated paid-exit rating facts.
    Ratings(PaidExitRatingsArgs),
    /// Create a buyer Cashu streaming payment envelope for a paid-exit session.
    #[command(name = "create-payment")]
    CreatePayment(PaidExitCreatePaymentArgs),
    /// Create a fallback fixed Cashu-token lease payment envelope.
    #[command(name = "create-token-lease")]
    CreateTokenLease(PaidExitCreateTokenLeaseArgs),
    /// Sign due buyer Cashu streaming balance updates from the local wallet.
    #[command(name = "stream-payments")]
    StreamPayments(PaidExitStreamPaymentsArgs),
    /// Settle and close a buyer Cashu streaming channel.
    Settle(PaidExitSettleArgs),
    /// Apply an incoming buyer Cashu streaming payment envelope as a seller.
    #[command(name = "apply-payment")]
    ApplyPayment(PaidExitApplyPaymentArgs),
    /// Queue a buyer payment envelope for direct FIPS delivery to the seller.
    #[command(name = "send-payment")]
    SendPayment(PaidExitSendPaymentArgs),
    /// Close a seller Cashu streaming channel and stop routing it.
    Collect(PaidExitCollectArgs),
    /// Close all expired seller Cashu streaming channels with pending credit.
    #[command(name = "collect-due")]
    CollectDue(PaidExitCollectDueArgs),
    /// Manage local paid-route wallet mint metadata.
    Wallet(PaidExitWalletArgs),
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum PaidExitOpinion {
    Up,
    Down,
    Clear,
}

#[derive(Debug, Args)]
struct PaidExitRateArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    /// Defaults to the currently selected provider.
    #[arg(long)]
    provider: Option<String>,
    #[arg(value_enum)]
    opinion: PaidExitOpinion,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct PaidExitStatusArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct PaidExitRunArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    /// Stable Nostr d-tag for this seller's paid-exit offer.
    #[arg(long)]
    offer_id: Option<String>,
    /// Publish the refreshed offer over Nostr pubsub.
    #[arg(long)]
    publish: bool,
    /// Do not ask a running daemon to reload after saving seller config.
    #[arg(long)]
    no_reload_daemon: bool,
    #[arg(long)]
    upstream: Option<String>,
    #[arg(long)]
    price_msat_per_gb: Option<u64>,
    /// Replace accepted Cashu mints with a comma-separated list. Empty clears them.
    #[arg(long)]
    accepted_mints: Option<String>,
    /// Add an accepted Cashu mint. Can be supplied more than once.
    #[arg(long = "accepted-mint")]
    accepted_mint: Vec<String>,
    #[arg(long)]
    country_code: Option<String>,
    /// Provider-declared residential, datacenter, mobile, business, or unknown network.
    #[arg(long)]
    network_class: Option<nostr_vpn_core::paid_routes::ExitNetworkClass>,
    #[arg(long)]
    asn: Option<u32>,
    #[arg(long)]
    max_channel_capacity_sat: Option<u64>,
    #[arg(long)]
    channel_expiry_secs: Option<u64>,
    /// Free traffic before payment. Accepts byte quantities such as "1 MB".
    #[arg(long, value_name = "UNITS")]
    free_probe_units: Option<String>,
    /// Extra unpaid traffic allowed after payment runs behind.
    #[arg(long, value_name = "UNITS")]
    grace_units: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct PaidExitOfferArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    /// Stable Nostr d-tag for this seller's paid-exit offer.
    #[arg(long)]
    offer_id: Option<String>,
    /// Publish the signed offer over Nostr pubsub.
    #[arg(long)]
    publish: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct PaidExitImportOfferArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    /// Signed Nostr paid-route offer event JSON. Omit with --event-stdin or --event-file.
    #[arg(long, conflicts_with_all = ["event_stdin", "event_file"])]
    event: Option<String>,
    /// Read signed offer event JSON from stdin.
    #[arg(long, conflicts_with = "event_file")]
    event_stdin: bool,
    /// File containing signed offer event JSON.
    #[arg(long, conflicts_with = "event_stdin")]
    event_file: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct PaidExitDiscoverArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    /// Import only signed offers accepted by this provider npub/link.
    #[arg(long)]
    provider: Option<String>,
    /// Wait up to this many seconds for the daemon's live discovery cache.
    #[arg(long, default_value_t = 0)]
    duration_secs: u64,
    #[arg(long, default_value_t = 50)]
    limit: usize,
    /// Ignore offer events older than this many seconds.
    #[arg(long, default_value_t = 86_400)]
    since_secs: u64,
    /// FIPS peer ratings JSON exported by `fipsctl ratings export`.
    #[arg(long = "fips-peer-ratings", value_name = "PATH")]
    fips_peer_ratings: Option<PathBuf>,
    /// Trusted Nostr pubkey/npub allowed to publish rating facts. Repeat or comma-separate.
    #[arg(long = "trusted-rating-author", value_name = "NPUB_OR_HEX")]
    trusted_rating_authors: Vec<String>,
    /// Rating scope to read from the ratings file.
    #[arg(long = "rating-scope", default_value = DEFAULT_PAID_EXIT_RATING_SCOPE)]
    rating_scope: String,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct PaidExitBuyArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    /// Store key, offer id, or seller npub of the paid-exit offer to buy.
    offer: Option<String>,
    /// Buy the highest-rated stored paid-exit offer; unknown sellers rank as neutral.
    #[arg(long = "best-rated")]
    best_rated: bool,
    /// Cashu mint URL to use. Defaults to a compatible wallet/default mint.
    #[arg(long)]
    mint: Option<String>,
    #[arg(long)]
    channel_capacity_sat: Option<u64>,
    #[arg(long, default_value_t = 0)]
    initial_paid_msat: u64,
    /// Keep the selected VPN exit unchanged after opening the paid session.
    #[arg(long)]
    no_select_exit_node: bool,
    /// Do not ask a running daemon to reload after selecting the paid exit.
    #[arg(long)]
    no_reload_daemon: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct PaidExitUseArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    /// Buyer paid-route session id.
    session: String,
    /// Do not ask a running daemon to reload after selecting the paid exit.
    #[arg(long)]
    no_reload_daemon: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct PaidExitProbeArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    /// Buyer or seller paid-route session id.
    session: String,
    /// Public-IP endpoint. Plain IP or JSON with ip/query/origin is accepted.
    #[arg(long)]
    ip_url: Option<String>,
    /// STUN server for realized public-IP probing. Defaults to configured NAT STUN servers.
    #[arg(long = "stun-server")]
    stun_servers: Vec<String>,
    /// Skip STUN realized public-IP probing and use HTTPS only.
    #[arg(long)]
    no_stun: bool,
    /// GeoIP endpoint template. Use {ip}; otherwise the IP is appended.
    #[arg(long)]
    geoip_url_template: Option<String>,
    /// Skip GeoIP country/ASN lookup.
    #[arg(long)]
    no_geoip: bool,
    /// Download endpoint for rough bandwidth measurement. Use {bytes} or a bytes query is appended.
    #[arg(long)]
    download_url: Option<String>,
    /// Upload endpoint for rough bandwidth measurement.
    #[arg(long)]
    upload_url: Option<String>,
    /// Bytes to transfer for each rough bandwidth direction.
    #[arg(long, default_value_t = DEFAULT_PAID_ROUTE_BANDWIDTH_BYTES)]
    bandwidth_bytes: u64,
    /// Skip rough bandwidth measurement.
    #[arg(long)]
    no_bandwidth: bool,
    /// Number of public-IP samples used for latency/jitter/loss.
    #[arg(long, default_value_t = 3)]
    samples: u8,
    #[arg(long, default_value_t = 5)]
    timeout_secs: u64,
    /// Do not ask a running daemon to reload after saving the probe result.
    #[arg(long)]
    no_reload_daemon: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct PaidExitRecordProbeArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    /// Buyer or seller paid-route session id.
    session: String,
    /// Realized public exit IP observed through this route.
    #[arg(long)]
    realized_exit_ip: Option<String>,
    /// Country code observed from realized exit IP geolocation.
    #[arg(long)]
    observed_country_code: Option<String>,
    /// ASN observed from realized exit IP geolocation.
    #[arg(long)]
    observed_asn: Option<u32>,
    #[arg(long)]
    latency_ms: Option<u32>,
    #[arg(long)]
    jitter_ms: Option<u32>,
    /// Packet loss in parts per million.
    #[arg(long)]
    packet_loss_ppm: Option<u32>,
    #[arg(long)]
    down_bps: Option<u64>,
    #[arg(long)]
    up_bps: Option<u64>,
    #[arg(long)]
    uptime_secs: Option<u64>,
    #[arg(long)]
    last_seen_unix: Option<u64>,
    /// Do not ask a running daemon to reload after saving the probe result.
    #[arg(long)]
    no_reload_daemon: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct PaidExitRatingsArgs {
    #[command(subcommand)]
    command: PaidExitRatingsCommand,
}

#[derive(Debug, Subcommand)]
enum PaidExitRatingsCommand {
    /// Export a signed rating fact event from a stored paid-exit probe.
    Export(PaidExitRatingsExportArgs),
    /// Publish a signed rating fact event from a stored paid-exit probe.
    Publish(PaidExitRatingsPublishArgs),
}

#[derive(Debug, Args)]
struct PaidExitRatingsExportArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    /// Buyer paid-route session id whose stored probe should rate the seller.
    #[arg(long)]
    session: String,
    /// Rating scope to write into the fact event.
    #[arg(long = "rating-scope", default_value = DEFAULT_PAID_EXIT_RATING_SCOPE)]
    rating_scope: String,
    /// Write `{ "events": [...] }` JSON to this path instead of stdout.
    #[arg(long)]
    output: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct PaidExitRatingsPublishArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    /// Buyer paid-route session id whose stored probe should rate the seller.
    #[arg(long)]
    session: String,
    /// Rating scope to write into the fact event.
    #[arg(long = "rating-scope", default_value = DEFAULT_PAID_EXIT_RATING_SCOPE)]
    rating_scope: String,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum PaidExitCreatePaymentKind {
    ChannelOpen,
    BalanceUpdate,
    CooperativeClose,
}

impl From<PaidExitCreatePaymentKind> for BuildPaidRouteBuyerPaymentEnvelopeKind {
    fn from(value: PaidExitCreatePaymentKind) -> Self {
        match value {
            PaidExitCreatePaymentKind::ChannelOpen => Self::ChannelOpen,
            PaidExitCreatePaymentKind::BalanceUpdate => Self::BalanceUpdate,
            PaidExitCreatePaymentKind::CooperativeClose => Self::CooperativeClose,
        }
    }
}

#[derive(Debug, Args)]
struct PaidExitCreatePaymentArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    /// Buyer session id.
    session: String,
    /// Payment envelope kind to create.
    #[arg(long, value_enum, default_value_t = PaidExitCreatePaymentKind::BalanceUpdate)]
    kind: PaidExitCreatePaymentKind,
    /// JSON CashuSpilmanPayment snapshot. Omit with --payment-stdin.
    #[arg(long)]
    payment: Option<String>,
    /// Read JSON CashuSpilmanPayment from stdin.
    #[arg(long, conflicts_with = "payment")]
    payment_stdin: bool,
    /// Fund/open the session's Cashu Spilman channel from the local wallet.
    #[arg(long, conflicts_with_all = ["payment", "payment_stdin", "sign_from_wallet"])]
    open_from_wallet: bool,
    /// Sign the payment from the local wallet's persisted Spilman client channel.
    #[arg(long, conflicts_with_all = ["payment", "payment_stdin", "open_from_wallet"])]
    sign_from_wallet: bool,
    /// Override the wallet mint used for --open-from-wallet.
    #[arg(long)]
    mint: Option<String>,
    /// Specific mint keyset id to use for --open-from-wallet.
    #[arg(long)]
    keyset_id: Option<String>,
    /// KeysetInfo JSON for --open-from-wallet. If omitted, fetch from mint.
    #[arg(long, conflicts_with = "keyset_info_file")]
    keyset_info: Option<String>,
    /// File containing KeysetInfo JSON for --open-from-wallet.
    #[arg(long, conflicts_with = "keyset_info")]
    keyset_info_file: Option<PathBuf>,
    /// Maximum value per Cashu output when opening a Spilman channel.
    #[arg(long, default_value_t = 64)]
    max_amount_per_output: u64,
    /// Delivered route units to report. Defaults to current session usage.
    #[arg(long)]
    delivered_units: Option<u64>,
    /// Paid amount in millisats. Defaults from the payment balance and Cashu unit.
    #[arg(long)]
    paid_msat: Option<u64>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct PaidExitCreateTokenLeaseArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    /// Buyer session id.
    session: String,
    /// Cashu token to pay the fixed lease. Omit with --token-stdin.
    #[arg(long, required_unless_present = "token_stdin")]
    token: Option<String>,
    /// Read Cashu token from stdin.
    #[arg(long, conflicts_with = "token")]
    token_stdin: bool,
    /// Cashu mint URL for the token. Defaults to the session mint.
    #[arg(long)]
    mint: Option<String>,
    /// Cashu token unit.
    #[arg(long, default_value = "sat")]
    unit: String,
    /// Token amount in the selected Cashu unit.
    #[arg(long, alias = "amount-sat")]
    amount: u64,
    /// Optional route credit in millisats. Defaults from the token amount and unit.
    #[arg(long)]
    paid_msat: Option<u64>,
    /// Override token lease expiry. Defaults to the selected session expiry.
    #[arg(long)]
    expires_at_unix: Option<u64>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct PaidExitStreamPaymentsArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    /// Build payment updates without queueing or changing local payment state.
    #[arg(long)]
    dry_run: bool,
    /// Only sign updates at least this many millisats above the last signed balance.
    #[arg(long, default_value_t = 1)]
    min_increment_msat: u64,
    /// Maximum number of due buyer sessions to update. Zero means no limit.
    #[arg(long, default_value_t = 0)]
    limit: usize,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct PaidExitSettleArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    /// Buyer session id.
    session: String,
    /// Build the close envelope without queueing or changing local payment state.
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct PaidExitApplyPaymentArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    /// JSON StreamingRoutePaymentEnvelope. Omit with --envelope-stdin.
    #[arg(long, required_unless_present = "envelope_stdin")]
    envelope: Option<String>,
    /// Read JSON StreamingRoutePaymentEnvelope from stdin.
    #[arg(long, conflicts_with = "envelope")]
    envelope_stdin: bool,
    /// Do not ask a running daemon to reload after applying a payment.
    #[arg(long)]
    no_reload_daemon: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct PaidExitSendPaymentArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    /// JSON StreamingRoutePaymentEnvelope. Omit with --envelope-stdin.
    #[arg(long, required_unless_present = "envelope_stdin")]
    envelope: Option<String>,
    /// Read JSON StreamingRoutePaymentEnvelope from stdin.
    #[arg(long, conflicts_with = "envelope")]
    envelope_stdin: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct PaidExitCollectArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    /// Seller channel id to close.
    channel: String,
    /// Do not ask a running daemon to reload after closing the channel.
    #[arg(long)]
    no_reload_daemon: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct PaidExitCollectDueArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    /// Maximum number of due seller channels to close. Zero means no limit.
    #[arg(long, default_value_t = 0)]
    limit: usize,
    /// Do not ask a running daemon to reload after closing due channels.
    #[arg(long)]
    no_reload_daemon: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct PaidExitWalletArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    json: bool,
    #[command(subcommand)]
    command: PaidExitWalletCommand,
}

#[derive(Debug, Subcommand)]
enum PaidExitWalletCommand {
    /// Show configured wallet mints and local Cashu wallet balances.
    Show(PaidExitWalletShowArgs),
    /// Create a Lightning invoice to top up the Cashu wallet.
    #[command(name = "topup", alias = "top-up")]
    Topup(PaidExitWalletTopupArgs),
    /// Receive/import a Cashu token into the wallet.
    #[command(alias = "import")]
    Receive(PaidExitWalletReceiveArgs),
    /// Inspect a Cashu token before choosing whether to redeem it.
    Inspect(PaidExitWalletReceiveArgs),
    /// Send/export a Cashu token from the wallet.
    #[command(alias = "export")]
    Send(PaidExitWalletSendArgs),
    /// Pay a Lightning invoice from the Cashu wallet.
    Withdraw(PaidExitWalletWithdrawArgs),
    /// Add or update an accepted Cashu mint.
    AddMint(PaidExitWalletAddMintArgs),
    /// Remove a Cashu mint.
    RemoveMint(PaidExitWalletMintUrlArgs),
    /// Set the default Cashu mint.
    SetDefault(PaidExitWalletMintUrlArgs),
}

#[derive(Debug, Args)]
struct PaidExitWalletShowArgs {
    /// Refresh pending mint quotes and incomplete sends before showing balances.
    #[arg(long)]
    refresh: bool,
    /// Include recent wallet activity.
    #[arg(long)]
    activity: bool,
}

#[derive(Debug, Args)]
struct PaidExitWalletTopupArgs {
    /// Amount to mint, in sats.
    amount_sat: u64,
    /// Cashu mint URL. Defaults to the configured wallet default mint.
    #[arg(long)]
    mint: Option<String>,
}

#[derive(Debug, Args)]
struct PaidExitWalletReceiveArgs {
    /// Cashu token. Omit with --token-stdin to read from stdin.
    token: Option<String>,
    #[arg(long)]
    token_stdin: bool,
}

#[derive(Debug, Args)]
struct PaidExitWalletSendArgs {
    /// Amount to send, in sats.
    amount_sat: u64,
    /// Cashu mint URL. Defaults to the configured wallet default mint.
    #[arg(long)]
    mint: Option<String>,
}

#[derive(Debug, Args)]
struct PaidExitWalletWithdrawArgs {
    /// BOLT11 invoice to pay.
    invoice: String,
    /// Cashu mint URL. Defaults to the configured wallet default mint.
    #[arg(long)]
    mint: Option<String>,
}

#[derive(Debug, Args)]
struct PaidExitWalletAddMintArgs {
    /// Cashu mint URL.
    url: String,
    #[arg(long)]
    label: Option<String>,
    #[arg(long)]
    balance_msat: Option<u64>,
    #[arg(long)]
    make_default: bool,
}

#[derive(Debug, Args)]
struct PaidExitWalletMintUrlArgs {
    /// Cashu mint URL.
    url: String,
}
