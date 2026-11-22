# Umbrel

This directory contains the Umbrel app template:

- `docker-compose.yml` runs `nvpn` with host networking and `/dev/net/tun`, and
  serves the control panel through Umbrel's app proxy.
- `docker-compose.local.yml` keeps the web service on loopback for local Docker
  testing.
- `umbrel-app.yml`, `icon.svg`, and `exports.sh` provide app metadata.
- `Dockerfile` builds the Svelte control panel, `nvpn`, and `nvpn-web` into one
  multi-stage image.

## Local validation

From the repository root:

```sh
docker compose -f umbrel/docker-compose.local.yml up --build -d
curl http://127.0.0.1:38080/api/health
curl -X POST http://127.0.0.1:38080/api/tick
```

Open <http://127.0.0.1:38080> for the UI. Stop the stack with:

```sh
docker compose -f umbrel/docker-compose.local.yml down
```

The focused browser/API test is:

```sh
just e2e-umbrel-web
```

Mesh packet-path behavior is covered by the backend Docker end-to-end tests.

## Running alongside AdGuard Home

Nostr VPN's Linux DNS listeners use `127.0.0.55`, leaving `127.0.0.1` and the
Umbrel's LAN addresses available to AdGuard. Native DNS can continue using an
existing resolver on `127.0.0.1` or `::1`.

An AdGuard listener bound to all interfaces still occupies `127.0.0.55:53`.
For mesh-only use with the Direct internet source and no connection protection,
Nostr VPN can continue with native DNS. Private names still require working
split-DNS support on the host. When an active exit or connection protection
requires secure DNS, Nostr VPN refuses to continue without that listener.

To use secure DNS alongside AdGuard Home, select specific LAN or localhost
addresses for AdGuard's DNS server and keep DNS on port 53. Keep the AdGuard
web interface on port 8095. Clients can continue using those addresses for DNS.

For an existing installation, stop AdGuard Home, set `dns.bind_hosts` in
`AdGuardHome.yaml` to the specific addresses your clients use, then restart
AdGuard Home. Leave `127.0.0.55` available for Nostr VPN.

## Release bundle

Umbrel submissions require a public, digest-pinned multi-architecture image.
Build, push, anonymously verify, and render the bundle with:

```sh
node scripts/umbrel-release.mjs \
  --push \
  --image-repo registry.example/namespace/nostr-vpn-umbrel
```

To reuse an already published image, pass its full
`repository:vX.Y.Z@sha256:...` reference:

```sh
node scripts/umbrel-release.mjs --image-ref "$IMAGE_REF"
```

The script requires `linux/amd64` and `linux/arm64`, verifies anonymous registry
readback, checks that the image tag matches the workspace version, and writes a
submission bundle under `dist/` without replacing an existing bundle.

## Limitation

The container manages the mesh tunnel and routes, but it does not install
MagicDNS split-DNS aliases on the Umbrel host.
