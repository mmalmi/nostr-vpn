# CDK 0.18 wallet migration trial — 2026-09-12

The local candidate upgrades the Cashu/CDK wallet family from **0.17.6 to
0.18.0**, while preserving the vendored **cdk-spilman 0.17.6** implementation
and its compatibility fixes. A real 0.17.6 loopback mint, simulated Lightning,
and two separately compiled wallet executables verified the database and
funded-channel transition. No live wallet, external funded mint, deployment,
or release was involved.

## Sources and dependency split

- Product baseline: `9439a1b594f9ea5238c053dab890f25cb24d9f88`.
- [CDK v0.18.0](https://github.com/cashubtc/cdk/releases/tag/v0.18.0), released
  2 September 2026, source `d3dec24c784e8fec1fd65f853241c7a2261c7abd`.
  The registry's latest stable Cashu, CDK and CDK SQLite versions were all
  0.18.0, not yanked, when checked on 12 September.
- `cashu`, `cdk`, `cdk-common`, `cdk-http-client`, `cdk-signatory`,
  `cdk-sql-common`, and `cdk-sqlite` resolve to 0.18.0. The local mint fixture
  also uses `cdk-axum` 0.18.0 when built with the candidate.
- `cashu-service` remains the vendored 0.4.8 adapter. Its explicit SDK pins
  and the Spilman library's Cashu pin are 0.18.0. Both product lockfiles select
  a single Cashu version and retain exact registry checksums.
- [Spilman provenance and earlier audit](../vendor/cdk-spilman/README.nvpn.md)
  remain unchanged. The author's unpublished, incompatible channel derivation
  changes were not adopted. The Spilman source adjustment only accommodates
  `CurrencyUnit::Custom(Arc<str>)`; channel IDs, secrets, commitment encoding,
  deterministic outputs and FIPS formats are unchanged.

The useful upstream improvements include atomic proof reservations and wallet
creation, stronger operation recovery, transaction status, deterministic quote
keys, and persisted request pacing. These support unattended wallet operation.
The mint operator's `cdk-mintd` configuration migration does not apply to our
wallet; its SQLite migrations run through the existing wallet open path.

## Adapter change

The removed `refresh_keysets()` cannot be replaced directly with
`keysets(KeysetLoadPolicy::Refresh)`: in 0.18 that API returns inactive keysets
and can silently fall back to cached metadata after a network failure.

Funding now calls `fetch_mint_info()`, whose underlying metadata refresh
propagates failures and refreshes the same keyset cache, then selects an active
keyset for the wallet unit with `CacheOnly`. The existing comparison against
the independently fetched Spilman funding keyset remains in place. Regression
tests cover rotation, another currency, a cheaper inactive keyset, no active
keyset, and a failed refresh with a populated cache.

Source: [0.18 keyset handling](https://github.com/cashubtc/cdk/blob/v0.18.0/crates/cdk/src/wallet/keysets.rs)
and [wallet metadata refresh](https://github.com/cashubtc/cdk/blob/v0.18.0/crates/cdk/src/wallet/mod.rs).

## Cross-version result

`scripts/check-cdk-migration` builds the baseline adapter and original Spilman
implementation from the product baseline commit, then builds the candidate.
It uses temporary directories and a loopback mint whose Lightning backend
only maintains synthetic accounting. Build dependencies may be downloaded
from the package registry. Temporary databases and executable artifacts are
removed when the script exits.

The baseline created 256 synthetic sat, committed 64 to a channel and left an
unclaimed 16-sat token send pending. Available balance was 176 sat. All baseline
wallet writers were closed before taking the test backup or starting the new
wallet process.

The candidate's production `CashuWalletService::open_file_backed` applied six
SQLite migrations, increasing the recorded migration count from 34 to 40:

```
20260617000000_add_updated_at_to_mint_quote.sql
20260723000000_add_transaction_status.sql
20260726000000_rekey_saga_transactions.sql
20260810000000_derivation_counter.sql
20260810000000_drop_mint_quote_created_time.sql
20260811000000_add_proof_derivation_index.sql
```

Verified outcomes:

- Available balance remained 176 after opening the migrated database.
- Recovery by the original request ID returned the exact original channel
  result, including identity and funding data.
- An oversized send failed without changing available funds.
- The pre-upgrade pending operation reclaimed exactly 16 sat, restoring 192.
- The old channel accepted a new 20-sat payment and settled to 20 sat for the
  receiver and 44 sat for the sender.
- Refund recovery imported 44 sat once; a repeated restore imported zero.
- Final spendable balances were **236 + 20 = 256 sat**, with conserved mint
  accounting.

A separate file-backed test exercises CDK's actual `prepare_send` failure:
16 sat covers the requested amount but cannot also cover input fees. The same
unspent proof and 16-sat balance survive the failed preparation and reopening
through the production service. Its mock proof metadata is never submitted
to a mint. The cross-version trial above uses authentic locally issued proofs.

## Backup and recovery boundary

The 0.17.6 executable successfully reopened a copy of the migrated fixture and
read its final 236-sat available balance. It also reopened the untouched
pre-upgrade backup and read 176 sat. This proves those specific open/read paths;
it does **not** establish safe downgrade or old-version writes. CDK's migration
runner applies missing migrations without rejecting unknown later migrations,
so successful opening alone is not a schema compatibility guarantee.

A recoverable pre-upgrade snapshot must keep the wallet database consistent
with its seed and channel stores, taken while their writers are stopped (or
using a separately verified consistent backup mechanism). SQLite WAL files
must not be omitted if they contain committed data. The trial copied the
entire synthetic buyer directory after closing its wallet and channel writers.

Restoring that snapshot after new mint operations is not a rollback of the
mint: the old backup still contains spent or reclaimed proofs and outdated
channel state. The backup was only opened for a balance read, never spent.
No recovery claim is made for arbitrary production history, crashes during
migration, platform keychains, or restoring after post-upgrade transactions.

## Focused verification

Commands run from the repository root; build profiles used debug information
disabled and incremental compilation disabled for the trial.

| Command | Result |
| --- | --- |
| `scripts/check-cdk-migration` | Passed; 34→40 migrations and all cross-version assertions above |
| `cargo test --manifest-path vendor/cashu-service/Cargo.toml --features simulation,spilman-wallet-http,spilman-configurable-host-reqwest` | 105 passed |
| `cargo test --manifest-path vendor/cdk-spilman/Cargo.toml --all-features` | 110 passed; 4 pre-existing doc examples ignored |
| `cargo test -p nostr-vpn-core --features cashu-wallet --lib paid_route_store` | 87 passed |
| `cargo test -p nostr-vpn-core --features cashu-wallet paid_routes` | 23 passed |
| `cargo test -p nostr-vpn-core --features cashu-wallet paid_exit` | 13 passed (some overlap with the prior filter) |
| `cargo test -p nvpn paid_exit` | 97 passed, including 6 CLI integration tests |
| `cargo check -p nvpn -p nostr-vpn-app-core` | Passed |
| `cargo tree --manifest-path linux/Cargo.toml -i cashu` | One Cashu 0.18.0 dependency family; Linux lock updated |

The old-to-old control run also passed before changing the dependency pins.
The reproducible cross-version script subsequently passed with freshly built
executables. These are focused local compatibility checks; platform builds,
device tests and the release gate remain outside this trial.
