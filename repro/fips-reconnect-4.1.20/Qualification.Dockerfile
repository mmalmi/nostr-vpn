# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM rust:1.94-bookworm@sha256:6ae102bdbf528294bc79ad6e1fae682f6f7c2a6e6621506ba959f9685b308a55 AS rust-builder
ARG TARGETPLATFORM
WORKDIR /work

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      clang \
      libclang-dev \
      libdbus-1-dev \
      pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY qualified-core /qualified-core
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY vendor ./vendor

RUN --mount=type=cache,id=nostr-vpn-umbrel-cargo-registry-${TARGETPLATFORM},target=/usr/local/cargo/registry \
    --mount=type=cache,id=nostr-vpn-umbrel-cargo-git-${TARGETPLATFORM},target=/usr/local/cargo/git \
    --mount=type=cache,id=nostr-vpn-umbrel-cargo-target-${TARGETPLATFORM},target=/work/target \
    cargo build --release --locked -p nvpn \
    && mkdir -p /out \
    && cp /work/target/release/nvpn /out/nvpn

FROM ghcr.io/mmalmi/nostr-vpn-umbrel@sha256:9786730835b9d810f7939f219b07f66f446675fdf4227d67328d15f7c0713f63 AS runtime
COPY --from=rust-builder /out/nvpn /usr/local/bin/nvpn
