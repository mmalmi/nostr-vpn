# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM node:24-bookworm@sha256:d862bb5d082c5ae0210ac07e8c0344cb8cf7bef6d78e9b8c50c179da923108ea AS web-builder
WORKDIR /work/web/control-panel

COPY web/control-panel/package.json web/control-panel/pnpm-lock.yaml ./
RUN --mount=type=cache,id=nostr-vpn-umbrel-pnpm-store,target=/pnpm/store \
    corepack enable \
    && pnpm install --frozen-lockfile --store-dir /pnpm/store

COPY web/control-panel ./
RUN pnpm run build

FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3 AS bookworm-index
ADD --checksum=sha256:796f1389bfea13c0ed78f663b765baaff54a508e5483786bd6ece73c5e3e3cbe https://curl.se/ca/cacert-2026-10-20.pem /tmp/nvpn-ca.pem
RUN install -D -m 0644 /tmp/nvpn-ca.pem /etc/ssl/certs/ca-certificates.crt \
    && rm -f /etc/apt/sources.list /etc/apt/sources.list.d/* \
    && rm -rf /var/lib/apt/lists/* \
    && printf '%s\n' \
      'deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg check-valid-until=no] https://snapshot.debian.org/archive/debian/20261027T000000Z bookworm main' \
      'deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg check-valid-until=no] https://snapshot.debian.org/archive/debian-security/20261027T000000Z bookworm-security main' \
      > /etc/apt/sources.list \
    && apt-get -o APT::Update::Error-Mode=any -o Acquire::Retries=2 -o Acquire::https::CaInfo=/etc/ssl/certs/ca-certificates.crt update \
    && printf '%s\n' \
      '77737fa4b34f2693e982cc9ee35736816c35a7778fc2d326cc1bbf5b301fe1aa  /var/lib/apt/lists/snapshot.debian.org_archive_debian_20261027T000000Z_dists_bookworm_InRelease' \
      'c04f97133debb797fa029bbc8ffe42fd5c8c039bad32cbb1e69cdbebce349b76  /var/lib/apt/lists/snapshot.debian.org_archive_debian-security_20261027T000000Z_dists_bookworm-security_InRelease' \
      | sha256sum --check --strict \
    && printf '%s\n' \
      'Dir::Etc::sourcelist "/snapshot/etc/apt/sources.list";' \
      'Dir::Etc::sourceparts "-";' \
      'Dir::State::lists "/snapshot/var/lib/apt/lists";' \
      'Acquire::https::CaInfo "/snapshot/etc/ssl/certs/ca-certificates.crt";' > /apt.conf

FROM rust:1.94-bookworm@sha256:6ae102bdbf528294bc79ad6e1fae682f6f7c2a6e6621506ba959f9685b308a55 AS rust-builder
ARG TARGETPLATFORM
WORKDIR /work

RUN --mount=type=bind,from=bookworm-index,target=/snapshot \
    apt-get -c /snapshot/apt.conf install -y --no-install-recommends \
      clang \
      libclang-dev \
      libdbus-1-dev \
      pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY vendor ./vendor

RUN --mount=type=cache,id=nostr-vpn-umbrel-cargo-registry-${TARGETPLATFORM},target=/usr/local/cargo/registry \
    --mount=type=cache,id=nostr-vpn-umbrel-cargo-git-${TARGETPLATFORM},target=/usr/local/cargo/git \
    --mount=type=cache,id=nostr-vpn-umbrel-cargo-target-${TARGETPLATFORM},target=/work/target \
    cargo build --release --locked -p nvpn -p nostr-vpn-web \
    && mkdir -p /out \
    && cp /work/target/release/nvpn /out/nvpn \
    && cp /work/target/release/nostr-vpn-web /out/nvpn-web

FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3 AS runtime
LABEL org.opencontainers.image.source="https://github.com/mmalmi/nostr-vpn" \
      org.opencontainers.image.description="Nostr VPN Umbrel app image" \
      org.opencontainers.image.licenses="MIT"

RUN --mount=type=bind,from=bookworm-index,target=/snapshot \
    apt-get -c /snapshot/apt.conf install -y --no-install-recommends \
      ca-certificates \
      iproute2 \
      iptables \
      iputils-ping \
      libdbus-1-3 \
      nftables \
      procps \
      wireguard-tools \
    && rm -rf /var/lib/apt/lists/*

COPY --from=rust-builder /out/nvpn /usr/local/bin/nvpn
COPY --from=rust-builder /out/nvpn-web /usr/local/bin/nvpn-web
COPY --from=web-builder /work/web/control-panel/dist /usr/share/nostr-vpn/web

ENV HOME=/data/home \
    XDG_CONFIG_HOME=/data/config \
    NVPN_CLI_PATH=/usr/local/bin/nvpn \
    RUST_LOG=info

EXPOSE 38080
VOLUME ["/data"]

ENTRYPOINT ["nvpn-web"]
CMD ["--listen", "127.0.0.1:38080", "--config", "/data/config/nvpn/config.toml"]
