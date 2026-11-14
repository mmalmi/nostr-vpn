# cashu-credit

Small, transport-neutral accounting primitives for peer-issued Cashu and paid useful service.
The crate owns no keys, sockets, wallets, or mint runtime. Applications serialize and sign receipt
claims with their existing identity system, validate Cashu proofs with a real Cashu library, and
then pass the verified peer identity into this deterministic state machine.

## Three value classes

- `peer_credit` is a sat-denominated, unbacked bilateral IOU. Per-issuer, aggregate, and offline caps bound risk. It
  can buy service or be novated to another trusted peer issuer, but can never authorize cashout.
- `closed_loop_deposit` is backed by deposits at its issuer. It can circulate among peers that
  accept that issuer or buy issuer service, but the ledger has no path to external settlement.
- `reserve_backed_withdrawable` is backed by a separate withdrawable sat reserve. This is the only
  ledger from which an external Cashu or Lightning settlement can be authorized.

Trusted third-party peer credit can replace bilateral debt without reducing total unbacked
exposure. Verified closed-loop value can replace it with a restricted backed liability. Verified
withdrawable value can replace it with cashout authority. Issuer-scoped ledgers prevent either of
the first two classes from borrowing another issuer's reserve through a transitive cashout.

Deposit calls record backing already verified by the wallet or mint adapter; they do not create or
verify Cashu proofs. Similarly, the caller must spend/check a proof before applying a backed receipt
or conversion. Keeping those production Cashu operations outside the accounting crate provides one
state machine without duplicating cryptography or mint behavior.

The receipt issuer is the party that requested or sponsored the service, not necessarily the packet
sender or recipient. Every receipt binds its meter to an application-defined `resource`: an FSP
adapter can name a destination/service/budget, while pubsub can name a subscription, nVPN a paid
route, and Hashtree an object. Applications remain authoritative about useful work: nVPN may meter
TCP ACK progress and outbound UDP cost, pubsub meters requested verified frames, and Hashtree meters
verified content blocks. Raw transport bytes, retransmissions, spam, and unsolicited data do not
become billable merely by reaching this crate. Backing deposits and conversions use stable adapter
operation IDs, so retries within one account cannot allocate the same proof or Lightning payment
twice. External-settlement authorizations bind the exact payout destination, principal,
fee ceiling, and expiry. The ledger reserves principal plus the fee ceiling before I/O, records the
verified fee on completion, and refunds only the unused reservation.

## Persistence

`CreditAccountSnapshotV1` is the authoritative, versioned JSON representation of an account. Its
Rust encoder is deterministic for a crate version, but it is not an RFC 8785/JCS or cross-language
canonical-byte contract. Decode it through `CreditAccountSnapshotV1::decode_json` and restore it through
`CreditAccount::from_snapshot`; both paths validate caps, conservation, operation records, and the
monotonic revision before constructing live state. `CreditAccount` intentionally has no unchecked
`Deserialize` path.

Existing LMDB, SQLite, browser, or file stores can persist that JSON as one opaque value and use its
revision for their own compare-and-swap. The optional `cashu-service/credit-store` feature is only a
small server-side SQLite blob-and-CAS convenience; it is not a second accounting schema, and
consumers do not need new storage adapters to use snapshots.

A store holding more than one account must also atomically claim
`backing/<issuer>/<deposit_id>` for the account ID in the same transaction as the snapshot revision
CAS. Account snapshots reject replay inside one account, but cannot by themselves stop one verified
proof, quote, or payment from being copied into another account. `cashu-service/credit-store`
performs this global binding in its SQLite transaction; generic stores must provide the equivalent.

The snapshot bytes and backing-claim index are trusted local state and must be integrity-protected
together when stored or synchronized through an untrusted medium. Structural validation does not
re-authenticate the historical signatures, Cashu proofs, or Lightning payments that adapters
verified before recording them.

After restoring an account, `pending_external_settlement_authorizations` returns owned copies of
the saved authorizations in deterministic settlement-ID order. A recovery worker can resume those
exact operations without a parallel accounting schema, then persist completion after verified
delivery.
