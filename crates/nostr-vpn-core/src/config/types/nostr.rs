#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum NostrPubsubMode {
    /// Disable the FIPS control pubsub service.
    Off,
    /// Exchange control events over connected FIPS peers without a relay client.
    Client,
    /// Exchange events over FIPS and bridge them to/from configured Nostr relays.
    #[default]
    Relay,
}

impl NostrPubsubMode {
    pub fn enabled(self) -> bool {
        self != Self::Off
    }

    pub fn forwarding(self) -> bool {
        self == Self::Relay
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Client => "client",
            Self::Relay => "relay",
        }
    }
}

impl std::str::FromStr for NostrPubsubMode {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" | "disabled" => Ok(Self::Off),
            "client" | "local" => Ok(Self::Client),
            "relay" | "forward" | "forwarding" => Ok(Self::Relay),
            _ => Err("expected one of: off, client, relay"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NostrPubsubConfig {
    /// `client` exchanges events only with FIPS peers; `relay` also bridges
    /// signed announcement/control events to configured Nostr relays.
    #[serde(default)]
    pub mode: NostrPubsubMode,
    #[serde(default = "default_nostr_pubsub_fanout")]
    pub fanout: usize,
    #[serde(default = "default_nostr_pubsub_max_hops")]
    pub max_hops: u8,
    #[serde(default = "default_nostr_pubsub_max_event_bytes")]
    pub max_event_bytes: usize,
}

impl NostrPubsubConfig {
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }

    pub fn normalize(&mut self) {
        // The old default fanout was not wired through: the transport used 8.
        // Preserve that replication floor and upgrade the old default pair.
        if self.fanout == 4 && self.max_hops == 2 {
            self.max_hops = default_nostr_pubsub_max_hops();
        }
        self.fanout = self.fanout.clamp(default_nostr_pubsub_fanout(), 32);
        self.max_hops = self.max_hops.clamp(1, 10);
        self.max_event_bytes = self.max_event_bytes.clamp(1024, 56 * 1024);
    }

    pub fn enabled(&self) -> bool {
        self.mode.enabled()
    }

    pub fn forwarding(&self) -> bool {
        self.mode.forwarding()
    }
}

impl Default for NostrPubsubConfig {
    fn default() -> Self {
        Self {
            mode: NostrPubsubMode::Relay,
            fanout: default_nostr_pubsub_fanout(),
            max_hops: default_nostr_pubsub_max_hops(),
            max_event_bytes: default_nostr_pubsub_max_event_bytes(),
        }
    }
}

fn default_nostr_pubsub_fanout() -> usize {
    8
}

fn default_nostr_pubsub_max_hops() -> u8 {
    4
}

fn default_nostr_pubsub_max_event_bytes() -> usize {
    56 * 1024
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NostrConfig {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relays: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disabled_relays: Vec<String>,
    /// Nostr private identity key in `nsec` or hex format.
    #[serde(default)]
    pub secret_key: String,
    /// Nostr public identity key in `npub` or hex format.
    #[serde(default)]
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_profile_id: Option<NostrIdentityId>,
    #[serde(default, skip_serializing_if = "NostrPubsubConfig::is_default")]
    pub pubsub: NostrPubsubConfig,
}

impl Default for NostrConfig {
    fn default() -> Self {
        let (secret_key, public_key) = generate_nostr_identity();
        Self {
            relays: default_relays(),
            disabled_relays: Vec::new(),
            secret_key,
            public_key,
            identity_profile_id: None,
            pubsub: NostrPubsubConfig::default(),
        }
    }
}
