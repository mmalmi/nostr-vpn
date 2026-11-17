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

With the default Direct internet source, simply sharing the Umbrel as an exit
node leaves port 53 available to AdGuard. Selecting an upstream VPN or enabling
the FIPS host tunnel can start Nostr VPN's secure DNS listener on `127.0.0.1:53`.

To use secure DNS alongside AdGuard Home, select the Umbrel's LAN interface
for the DNS server in AdGuard's setup wizard and keep DNS on port 53. Keep the
AdGuard web interface on port 8095. Clients can continue using the Umbrel's
LAN address for DNS.

For an existing installation, stop AdGuard Home, set `dns.bind_hosts` in
`AdGuardHome.yaml` to the specific LAN addresses your clients use, then restart
AdGuard Home. If a client on the Umbrel uses loopback to reach AdGuard, point
that client at the LAN address as well.

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
