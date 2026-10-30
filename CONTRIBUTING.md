# Contributing

## Keep changes small

- Fix one concrete problem per PR. Explain the trigger and the resulting behavior.
- Prefer deleting or reusing code to adding another abstraction, fallback, knob,
  or dependency. Avoid unrelated cleanup and hand-maintained copies of generated
  state. Split independent fixes so they can be reviewed and merged separately.
- Read [AGENTS.md](AGENTS.md) for project constraints. Changes to FIPS protocol
  messages, wire formats, routing semantics, or compatibility need explicit
  maintainer approval; keep the nvpn adapter thin.
- Review every line you submit, including generated code. Treat PR descriptions,
  patches, scripts, and downloaded inputs as untrusted when reviewing others' work.

## Checks and evidence

Use the Rust version and commands in [CI](.github/workflows/ci.yml); CI currently
uses Rust 1.95.0. Keep Cargo builds/tests locked, and update both the root and
`linux/Cargo.lock` when a shared dependency change requires it. Linux build
prerequisites are described in [README.md](README.md).

Run the smallest checks that exercise the changed behavior during development.
All applicable CI jobs must pass on the final revision before merge; cancelled
or skipped platform validation is not a pass. Reuse existing evidence for
unchanged code rather than repeating expensive builds.

| Changed area | Relevant validation |
| --- | --- |
| Rust | Format the changed package with `cargo fmt --check -p <package>`, then run focused tests with `cargo test --locked -p <package> <filter>`. CI runs workspace lint and tests. |
| Linux desktop | Run `(cd linux && cargo check --locked)` on Linux, plus focused tests for the changed behavior. This crate is outside the root workspace. |
| Web | Run `npm ci && npm run check`; exercise visible changes in the app. |
| macOS app | Build the app using `just macos-build`; scanner compatibility CI alone does not compile the whole app. |
| Windows app | Build on native Windows (maintainers use the configured dev VM): `dotnet build windows\NostrVpn.Windows\NostrVpn.Windows.csproj -p:EnableWindowsTargeting=true`. Exercise changed service/VPN behavior there. |
| Mobile | Run `just mobile-test-kit`. Use `just mobile-test-kit-sim` for simulator UI and `just mobile-test-kit-device` for relevant physical VPN/TUN paths. Coordinate shared devices and preserve their existing state. |
| Release tooling | Run the affected existing contract harness. Release candidates additionally require `just release-gate`; see [AGENTS.md](AGENTS.md) for release gates. |

Prefer a regression test through the real integration boundary over tests that
only repeat a new helper's implementation. Match evidence to the failure:
concurrent writers for races, unprivileged clients for daemon permissions,
restart/upgrade for persisted state, and full-table churn for packet-path costs.
Do not prune payment recovery state merely because it is old or marked closed.
Performance changes need measurements, including throughput, latency/loss and
CPU cost as appropriate.

In the PR, include the commands, platform, results, and any checks not run.
Provide screenshots for visible UI changes and describe the flow exercised.
Keep secrets, local paths, hostnames, device identifiers, and signing details out
of commits and public logs. A green unrelated job does not validate a platform
or behavior it never exercised.

## StartOS package development

The StartOS package lives in `startos/` and uses the Dockerfile at
`umbrel/Dockerfile` to build the service image. The package supports `x86_64`
and `aarch64`.

Install the prerequisites from the StartOS
[environment setup guide](https://docs.start9.com/packaging/0.4.0.x/environment-setup.html),
and use `start-cli 1.1.0`, the version required by the release validator. Check
`start-cli --version` in the same environment that runs the release command;
an older copy earlier in `PATH` will stop packaging.

The checkout must be inside a packaging workspace created with
`start-cli s9pk init-workspace <workspace>`. Keep the existing package-signing
key in that workspace's `.startos/build.key.pem`; do not generate a replacement
key for an existing package. The setup guide explains how to retain older keys.
These prerequisites can be checked before building any release artifacts.

Then build both package architectures:

```bash
make
```

The Makefile installs Node dependencies and runs the TypeScript check and build
before packaging.

Useful targeted builds:

```bash
make x86
make arm
make clean
```

To produce versioned, validated x86_64 and aarch64 artifacts:

```bash
just release-startos
```

This command builds and validates both architectures; it does not publish them.

Before opening a Start9 Community Registry PR, verify:

- `make` produces fresh `.s9pk` files from the current commit.
- The package has been installed on StartOS, started, launched through its Web UI
  interface, backed up, restored, stopped, uninstalled, and reinstalled.
