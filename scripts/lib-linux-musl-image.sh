#!/usr/bin/env bash

# Registry manifest bytes were SHA-256 verified on 2026-10-28. Select the
# established amd64 cross-builders, independently of the Docker host platform.
linux_musl_default_image() {
  case "$1" in
    i686-unknown-linux-musl)
      printf '%s\n' 'messense/rust-musl-cross:i686-musl@sha256:13f4067cf1132c7ba5ecedce0158b1195432d3672fd0bbbe0bd56f3693fd8b0e' ;;
    x86_64-unknown-linux-musl)
      printf '%s\n' 'messense/rust-musl-cross:x86_64-musl@sha256:fb7229c2a7dd84957e3a46f8bec7d01c4ec7c295ad159606623093a0a9286253' ;;
    aarch64-unknown-linux-musl)
      printf '%s\n' 'messense/rust-musl-cross:aarch64-musl@sha256:c9403b20663fca32f703b4201672120d8a634d5ebcaf95d013f0140382432a17' ;;
    arm-unknown-linux-musleabihf)
      printf '%s\n' 'messense/rust-musl-cross:arm-musleabihf@sha256:fed9b69269f9fa9f37b283c0186bec08c251503ba2483bc26d11d041c5107356' ;;
    *) echo "unsupported Linux musl target: $1" >&2; return 2 ;;
  esac
}

linux_require_immutable_image() {
  [[ "$1" =~ ^sha256:[0-9a-f]{64}$ || "$1" =~ ^[^[:space:]]+@sha256:[0-9a-f]{64}$ ]] || {
    echo 'Linux builder requires a registry digest or full local image ID; mutable image tags are refused' >&2
    return 2
  }
}
