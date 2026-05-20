//! Namecoin `.bit` alias resolution for Nostr VPN.
//!
//! Resolves human-readable `.bit` names (e.g. `alice@example.bit` or
//! `example.bit`) to 32-byte hex Nostr pubkeys by walking the Namecoin
//! name tree via `ElectrumX`. The semantics follow the ifa-0001 Domain Name
//! Object and the NIP-05-over-Namecoin / "N1" track that has been deployed
//! by other Nostr clients (Amethyst, nostr-tools, Nostur, dart-nostr, strfry).
//!
//! Lookup procedure:
//!
//! 1. Strip the `.bit` suffix and split off any subdomain labels.
//! 2. Look up `d/<root>` on an `ElectrumX` server via `blockchain.name.get`.
//! 3. Parse the value as JSON. Walk the `map` subtree using ifa-0001
//!    semantics for any leading subdomain labels.
//! 4. Read `nostr.names[<local>]` (or `nostr.names["_"]` for an apex
//!    request without an explicit localpart) and return that hex pubkey.
//! 5. Honour a single `import` redirect when encountered (v1 limit).
//!
//! The crate ships an in-process TTL cache so back-to-back lookups for the
//! same name don't hammer `ElectrumX`.

#![forbid(unsafe_code)]

pub mod alias;
pub mod cache;
pub mod electrumx;
pub mod mock;
pub mod resolver;

pub use alias::{BitAlias, parse_bit_alias};
pub use cache::CachingResolver;
pub use electrumx::{ElectrumXResolver, ElectrumXServer};
pub use mock::MockResolver;
pub use resolver::{NamecoinError, NamecoinResolver, ResolverConfig};
