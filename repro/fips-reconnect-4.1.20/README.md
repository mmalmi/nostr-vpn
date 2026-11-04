# Reconnect qualification source

This records the source behind the Linux amd64 reconnect qualification artifact.
It combines Nostr VPN commit `5e8c0efd322c8ae3fdb18e212fbfd1b012046cd9`
with four reviewed FIPS changes from `362d7ce45f11ee39d41ad025f9776a1c2311d48e`.
The existing registry package versions and dependency graph are preserved.

Run `python3 repro/fips-reconnect-4.1.20/prepare.py /path/to/new/context`
from this checkout. The command obtains the original registry archive using its
pinned checksum, applies the reviewed patch, and verifies every reconstructed
file against the recorded qualification context. An existing copy of the same
crate can be supplied with `--crate`. Reconstruction performs no compilation.

`Qualification.Dockerfile` is the exact historical recipe. `Independent.Dockerfile`
adds empty Rust-cache checks for the independent compiler run. Both produced the
daemon SHA-256 recorded in `inputs.json`. The original image and forced-fresh
image have different digests because their timestamps differ. The daemon,
runtime file contents, ownership, modes and settings match.

These historical recipes pin the Rust compiler and runtime base images and the
Cargo dependency inputs. They use mutable Debian package indexes. The recorded
independent rebuild fetched OS packages from those mutable indexes and produced
the same daemon bytes. It does not establish a fully pinned rebuild of those
OS packages. Nostr VPN's successor recipe pins
the Debian snapshot indexes separately.

The recorded image identifies the qualification artifact. Deployment admission,
rollback and service acceptance are separate checks. The original v4.1.20
release manifest describes different daemon bytes.
