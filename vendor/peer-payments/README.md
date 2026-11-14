# Peer payments

Shared, local service-credit accounting for applications. Amounts are denominated
in sats; a debt to a particular peer is not bitcoin and cannot authorize a
Lightning withdrawal. This crate builds on `cashu-credit`, owns no network or
identity, and adds no consensus system.

`AccountStore` is the authoritative journal for one node's buying, selling and
reciprocal settlement across services. Applications supply identity keys, local
trust decisions, price/resource definitions and independent service evidence.
Use one store in a private application-state directory, not one per service.

`Controller` implements the signed quote, acceptance, receipt/acknowledgement and
reciprocal-settlement transitions on that store. `PurchaseIntent` must come from
the local service request: the controller checks the selected provider, resource,
service, exact capacity, price ceiling and duration before signing. Never derive
the intent from an unsolicited remote offer. `ControlMessage` provides a bounded,
versioned application envelope; applications authenticate the carrier and check
the expected response variant. A decoded message alone grants no authority.

`open` reserves one full service window atomically. Retrying it returns the saved
grant with no second window, including after restart. If the original window is
lost, its reservation stays consumed. Automatic netting has one initiator (the
smaller public key); a lost reply resends the exact persisted proposal. Quotes
are not reservations: simultaneous acceptance can still exhaust the provider's
budget, and rejected or unanswered purchases need reconciliation rather than a
timeout refund. All transitions can fail closed at the configured history and
spending limits.

`Controller::set_enabled(false)` persists the opt-out for both buying and selling
and revokes installed service windows. Re-enabling never revives those windows.
Receipts and settlement of existing obligations remain possible while disabled.
If saving the opt-out fails, live windows are still revoked; report the error
because the disabled setting was not durably saved.

The normal controller sequence is:

1. Provider signs immutable terms describing a precise service and resource.
2. Buyer persists `prepare_purchase` before signing those terms.
3. Provider persists `accept` and `reserve_window` before installing its returned
   `Allowance` at the existing service admission boundary.
4. Buyer persists `authorize_receipt` before signing cumulative verified usage.
   Provider checks its own meter and persists `apply_receipt` before acknowledging.
5. After both sides have provided services, `prepare_reciprocal` selects completed
   opposite debts. Each side persists the exact proposal before signing. Both
   signatures allow `commit_netting` to clear equal debts in one local transaction.

Nostr-compatible BIP340 signatures cover a domain-separated, versioned message
and the full agreement commitment. Keys stay with the embedding application.
Network adapters must limit frames before buffering them; `WireMessage::decode`
also bounds decoded control messages. Never deserialize an account from a peer.

Durable reservations include all uncertain work. Lost messages, failed saves,
unconfirmed sends, expiry and restart never return spending authority. A window
has one owner and cannot be cloned or restored. Closing an agreement or dropping
its store revokes live windows. The store uses a permanent owner lock and SQLite
revision checks. Missing/corrupt state fails closed; do not recreate it or delete
the `.owner` file as a recovery mechanism. Backups must include SQLite WAL state.

Automation is enabled in the policy defaults, but no stranger receives credit.
The optional `social-graph` feature finds direct contacts and contacts one
further hop away through an unmuted intermediary. `QuotePeers` compares signed
offers against independently supplied purchase intents, preferring the lower
total price and then the closer contact. Signed follow and mute events are
verified by the host application. No credit or signed acceptance is created by
discovery. The shared Cashu wallet also uses this graph when comparing signed
two-mint exchange quotes for an existing local order. Local acceptance policy and aggregate/per-peer caps must precede any
agreement. Reciprocal settlement never creates withdrawable assets, resets a
buyer's spending limit or allows an expired agreement to grant new service.

This is a development foundation. It includes bounded journals, exact-message
recovery, cumulative receipts and bilateral netting. It does not yet implement
automatic app discovery or activation, history compaction, arbitrary multi-issuer
exchange, blind service tokens or Lightning-node provisioning. Retained-history
and lifetime spending limits deliberately stop admission when exhausted. The
controller and packet adapters in FIPS and nVPN are integration APIs, not an automatic rollout.
Existing Cashu payment controllers remain in charge of their existing sessions.

Run `cargo test -p cashu-credit -p peer-payments --all-features`. The integration simulation covers
cross-service caps, 64 replay/reordering schedules, Sybil pressure, signature and
term substitution, failed commits, stale ownership, restart, revocation, signed
controller retries, local purchase intent and asymmetric reciprocal settlement.
It proves bounded accounting and tested native
adapter behavior, not economic solvency or production network performance.
