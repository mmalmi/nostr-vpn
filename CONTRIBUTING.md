# StartOS package development

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

The StartOS CLI 1.1.0 download must match the reviewed SHA-256 before use:

| Asset | SHA-256 |
| --- | --- |
| `start-cli_aarch64-macos` | `668acc728e173b6d36bddc26936d546d049a0fc26c5dc2cd6c5ef98f71a33ec1` |
| `start-cli_x86_64-linux` | `70eff67b6e9a936acd8aaaf787b783819252ecedaa5c74d462e3b15ed4dd843a` |

The shared StartOS/Umbrel container recipe pins its multi-architecture base
images and Dockerfile frontend by digest, and uses the committed Cargo and
pnpm locks. It builds on Debian Bookworm with Rust 1.94 and Node 24 for Linux
AMD64 and ARM64. Its system dependencies include Clang/libclang, D-Bus,
WireGuard tools, nftables, iptables and iproute2. Debian package repositories
remain external build inputs; these pins alone do not establish a byte-for-byte
binary reproduction. Keep the resolved image and package evidence with a build.

The pinned StartOS CLI internally invokes `ghcr.io/start9labs/sdk/utils:latest`.
The Makefile pulls that helper by a committed multi-architecture digest, binds
the CLI's required local tag to it, and checks the image identity before and
after packing. A changed helper causes the package build to fail and deletes
the output. Serialize StartOS packaging that uses this tag on one Docker daemon.
Keep that daemon local to the packaging workspace so the CLI's temporary bind
mounts resolve; a separate native Buildx builder may perform compilation.

Then build both package architectures:

```bash
make
```

The Makefile installs Node dependencies and runs the TypeScript check and build
before packaging. It uses `npm ci` and refuses a stale dependency lock; update
and commit `package-lock.json` explicitly when changing package dependencies.

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
