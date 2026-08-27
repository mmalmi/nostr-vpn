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
