This maintained fork is published as `nvpn-cdk-spilman`; the Rust library name
remains `cdk_spilman`. It is not an upstream Spilman release.

## Opt-in payout format

`ChannelParameters::output_version` distinguishes legacy output bytes from
the NUT-10 list encoding (`ChannelOutputVersion::Nut10`, wire value `2`).
Existing constructors and missing stored/wire values retain the legacy format;
unknown or malformed versions are rejected. Version 2 adds a domain separator
to the channel ID and emits `"tags":[]` for both parties' payout secrets.
It is a local format extension, not an upstream Spilman version.

Select it only **before funding**, after both peers have agreed to it. Never
rewrite a funded channel's parameters or already signed coins. VPN signed
listing/session version 5 commits new channels to output version 2. Version 4
remains readable for saved agreements; the wallet recovers existing legacy
channels but refuses fresh legacy funding. Both peers use the saved quote,
not a later listing, and reject format changes before processing payment.
The versioned local wallet command prevents older daemons from silently
ignoring the selection. Tests retain a
pre-change legacy derivation fingerprint, exercise peer/storage round trips,
verify minted output signatures, and reject cross-version funding proofs.

Strict NUT-10 mints reject legacy `tags:null` payouts. Already-issued legacy proofs cannot
be converted by editing their secrets; the issuing mint must accept their
original signed bytes for those funds to be redeemed.

### Payout correction acceptance

The source and test definitions below are a candidate, not a completed mint or
platform qualification. Run on a native development host with measured capacity and Rust
1.95.0, its platform C compiler and an existing compatible Cargo cache. Dependencies
are fixed by the root lockfile. The Linux workspace has its own updated lockfile.
No external mint, Lightning backend, user wallet or downloaded helper is needed.

Keep one writer on the stable `CARGO_TARGET_DIR`, limit compilation to
two jobs, and retain full command logs and exit statuses. Check free space before
starting; the initial qualification budget is 20 minutes plus two minutes for
closure, 4 GiB of growth in the owned Cargo target, 12.5 GiB free at entry and an
8.5 GiB free-space floor. Stop and inspect on any failed phase
or exceeded bound; do not start a second cache or retry unchanged failures.

```sh
# CARGO_TARGET_DIR and profile settings must match the shared cache.
export NVPN_REFUND_EXPECTED_COMMIT="$(git rev-parse HEAD)"
# Invoke under a controller locking that Cargo target, with the limits above.
bash scripts/check-spilman-payouts work/refund-qualification
```

The script pins Cargo to 1.95.0, runs the seven selected test phases offline with
the lockfile, stops on the first failure or zero-test selection, and saves full
phase logs plus exit codes and passing test counts. The outer native controller
owns time/disk monitoring and process-group closure. Independent work may run
alongside these checks when measured CPU, memory, disk and I/O capacity permit;
readiness checks do not reserve the whole host. Preserve existing active locks.
After a corrected failure, a second argument selects the first remaining phase
(for example, `payout-spend`). Reuse earlier evidence only when its tested source,
dependencies, toolchain and profile inputs are unchanged; skipped phases are not
reported as new passes.

`spilman_payout_spend` runs actual CDK mint signature, spending-condition and
double-spend validation behind a loopback boundary that additionally enforces
NUT-10's tag arrays. Only Lightning is simulated. It funds 64 test sats, restarts
the buyer without funding twice, pays 20, closes, restores 44 exactly once, and
spends both parties' payouts into a separate wallet. Malformed tags, unsigned
proofs and replayed tokens must fail; the recipient must finish with exactly 64.
This is an offline CDK integration fixture, not a claim of independent Nutshell
or live-mint acceptance.

The other tests preserve the legacy derivation fingerprint and issued proofs,
check wallet quarantine/restart, reject fresh legacy funding and unknown legacy
seller admissions, retain existing version-4 agreements, bind version 5 to output
version 2, and reject mismatches before wallet/receiver mutation. A new wallet
command must fail on old daemons instead of silently funding the old format.

After these checks pass, the release owner must integrate the exact commit,
publish the changed maintained libraries under new versions, qualify affected
desktop/Android and mobile build paths, and rebuild affected release artifacts.
Existing device and binary receipts do not certify this payment change. FIPS
dataplane message types, wire records and routing remain unchanged.

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

- Preserve the route's requested capacity when funding proofs contain extra
  value. Bind that capacity into the existing signed parameters before funding,
  reject insufficient tokens before spending them, and return the remainder to
  the sender at settlement. Renewal and idempotent recovery keep the same limit.
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
audit or a live-mint/platform release certification. Legacy channel IDs, key
derivation and commitment encoding remain unchanged. The opt-in format above
applies only to new contracts; FIPS protocol formats are unchanged.
