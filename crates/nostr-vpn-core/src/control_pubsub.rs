pub const CONTROL_PUBSUB_MAX_WIRE_BYTES: usize = 60 * 1024;
pub const CONTROL_PUBSUB_MAX_EVENT_BYTES: usize = 56 * 1024;
pub const FIPS_PEER_ADVERT_KIND: u16 = 37_195;
pub const PAID_EXIT_OFFER_KIND: u16 = 37_196;
pub const RATING_FACT_KIND: u16 = 7_368;

/// Durable control events shared by the daemon and standalone consumers.
pub fn control_pubsub_store_path(config_path: &std::path::Path) -> std::path::PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("control-pubsub-events.json")
}
