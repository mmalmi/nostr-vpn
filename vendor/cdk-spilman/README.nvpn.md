# Spilman dependency review — 2026-09-11

This directory contains the published `cdk-spilman` 0.17.6 source, with
compatibility-preserving fixes for nVPN. Both the main workspace and the
standalone Linux workspace select it through `[patch.crates-io]`.

## Provenance and update decision

- Original author: [SatsAndSports](https://github.com/SatsAndSports/cashu_spilman_channels).
- Published base: [cdk-spilman 0.17.6](https://crates.io/crates/cdk-spilman/0.17.6),
  package SHA-256 `7619b421495cb5fe74b60d9861072ccc8af6debd2836f3588ef2f81502c187e8`.
  Package VCS metadata identifies `6721f6d25a48b339c444536347e3c6c6b475b2a5`.
- Author main inspected at `267d934ab6c260f740baf5586fba91751d526fc6`. The newer
  source has an unpublished version reset to 0.1.0 and changes channel IDs,
  secret derivation, and deterministic outputs. Replacing the published base
  wholesale would require a migration strategy for existing funded channels.
- Cashu/CDK dependencies move together from 0.17.3 to **0.17.6**, also used by
  the author's current implementation. [0.17.4](https://github.com/cashubtc/cdk/releases/tag/v0.17.4)
  improves offline wallet startup and quote concurrency;
  [0.17.5](https://github.com/cashubtc/cdk/releases/tag/v0.17.5) improves settlement consistency.
- The SDK migration to [0.18.0](https://github.com/cashubtc/cdk/releases/tag/v0.18.0)
  was initially deferred. The [12 September compatibility trial](../../docs/cdk-018-migration-trial.md)
  now updates Cashu/CDK to 0.18.0 while retaining this Spilman 0.17.6 base and
  its channel derivations. The only additional Spilman source adaptation is
  conversion to Cashu's shared-string currency representation.

## Local fixes

- Bind channel currency to the mint keyset and reject replacement parameters
  on existing channels, including funding, payment and close retries.
- Stop accepting ordinary payments when sender refunds become available;
  settlement and same-balance closing-signature recovery remain available.
- Validate funding proof denominations, keysets, checked totals and output
  limits before deriving potentially large deterministic output lists.
- Charge funding swap fees using the actual input proof count. This incorporates
  the relevant correction from [author commit 5a7bc674](https://github.com/SatsAndSports/cashu_spilman_channels/commit/5a7bc674cf7d942ea1cc7db3ad2cbe1382de23f8).
- Keep the original signed allocation when settlement uses a rotated output
  keyset with different fees. Validate signature amounts/keysets and both
  parties' totals before accepting a settlement result.
- Reject malformed restore response counts, unrelated outputs and wrong
  denominations. This incorporates [author commit a7d03be4](https://github.com/SatsAndSports/cashu_spilman_channels/commit/a7d03be421c17c90d1aa8f4fc24fe7ca225a10df).
  Preserve transport errors and the existing ability to discover and recover
  proofs from their actual issuing keyset after rotation.

The adjacent `cashu-service` adapter also binds route currency to channel
funding and creates receiver keys atomically with private permissions. The
VPN validates advertised channel terms against the funded parameters.

## Verification and limits

Regressions exercise public channel construction, authentic mint DLEQ
signatures, payment/close processing, malformed restore responses, replay,
expiry and concurrent file-backed receiver startup. The existing Spilman,
wallet and paid-route suites also exercise the updated dependency family.

Passed checks:

| Check | Passing tests |
| --- | ---: |
| Spilman library, all features | 110 |
| Cashu service, all features | 102 |
| Core paid-route tests after integration with current master | 85 |
| Daemon paid-exit runtime tests after integration | 78 |
| Paid-exit CLI integration | 6 |
| Shared mobile Rust kit | 228 app-core + 12 platform-routing |

This is a focused source audit and regression suite, not a formal cryptographic
audit or a live-mint/platform release certification. Channel IDs, key
derivation, commitment encoding and FIPS protocol formats are unchanged.
