#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ANDROID_DIR="${REPO_ROOT}/crates/nostr-vpn-gui/src-tauri/gen/android"
KEY_PROPERTIES_PATH="${ANDROID_DIR}/key.properties"
ZAPSTORE_ENV_FILE="${REPO_ROOT}/.env.zapstore.local"
ZAPSTORE_CONFIG="${ZAPSTORE_CONFIG:-${REPO_ROOT}/zapstore.yaml}"
APK_PATH="${APK_PATH:-}"

if [ -f "${ZAPSTORE_ENV_FILE}" ]; then
  set -a
  # shellcheck disable=SC1090
  . "${ZAPSTORE_ENV_FILE}"
  set +a
fi

cd "${REPO_ROOT}"

ANDROID_KEYSTORE_PATH="${ANDROID_KEYSTORE_PATH:-}"
ANDROID_KEY_ALIAS="${ANDROID_KEY_ALIAS:-}"
ANDROID_KEYSTORE_PASSWORD="${ANDROID_KEYSTORE_PASSWORD:-}"
ANDROID_KEY_PASSWORD="${ANDROID_KEY_PASSWORD:-${ANDROID_KEYSTORE_PASSWORD}}"
DEFAULT_ANDROID_KEY_ALIAS="nostr-vpn-upload"
KEYSTORE_DNAME="${KEYSTORE_DNAME:-CN=Nostr VPN, OU=Mobile, O=Iris, L=Helsinki, S=Uusimaa, C=FI}"
NOSTR_KEY_PATH="${NOSTR_KEY_PATH:-}"
ZAPSTORE_CHANNEL="${ZAPSTORE_CHANNEL:-main}"
ZSP_EXTRA_FLAGS="${ZSP_EXTRA_FLAGS:-}"
ZSP_AUTO_CONFIRM="${ZSP_AUTO_CONFIRM:-1}"
ZSP_SKIP_PREVIEW="${ZSP_SKIP_PREVIEW:-1}"
INSTALL_ON_DEVICE="${INSTALL_ON_DEVICE:-0}"
CAPTURE_SCREENSHOT="${CAPTURE_SCREENSHOT:-0}"
SCREENSHOT_PATH="${SCREENSHOT_PATH:-${REPO_ROOT}/artifacts/android/nostr-vpn-home.png}"
SKIP_PUBLISH="${SKIP_PUBLISH:-0}"
PNPM_STORE_DIR="${PNPM_STORE_DIR:-${HOME}/.pnpm-store}"
LINK_SIGNING_CERT="${LINK_SIGNING_CERT:-}"
ZAPSTORE_IDENTITY_RELAY="${ZAPSTORE_IDENTITY_RELAY:-wss://relay.zapstore.dev}"

if [ -z "${LINK_SIGNING_CERT}" ]; then
  if [ "${SKIP_PUBLISH}" = "1" ]; then
    LINK_SIGNING_CERT="0"
  else
    LINK_SIGNING_CERT="1"
  fi
fi

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

cleanup() {
  rm -f "${KEY_PROPERTIES_PATH}"
  if [ -n "${TEMP_P12_PATH:-}" ]; then
    rm -f "${TEMP_P12_PATH}"
  fi
  if [ -n "${TEMP_IDENTITY_EVENT_PATH:-}" ]; then
    rm -f "${TEMP_IDENTITY_EVENT_PATH}"
  fi
  if [ -n "${TEMP_P12_DIR:-}" ]; then
    rmdir "${TEMP_P12_DIR}" 2>/dev/null || true
  fi
}

trap cleanup EXIT

require_cmd keytool
require_cmd zsp
if [ "${LINK_SIGNING_CERT}" = "1" ]; then
  require_cmd nak
fi

if [ -z "${APK_PATH}" ]; then
  require_cmd pnpm
  require_cmd rustup
fi

if [ "${INSTALL_ON_DEVICE}" = "1" ] || [ "${CAPTURE_SCREENSHOT}" = "1" ]; then
  require_cmd adb
fi

if [ -z "${ANDROID_SDK_ROOT:-}" ] && [ -d "${HOME}/Library/Android/sdk" ]; then
  export ANDROID_SDK_ROOT="${HOME}/Library/Android/sdk"
fi

if [ -z "${ANDROID_HOME:-}" ] && [ -n "${ANDROID_SDK_ROOT:-}" ]; then
  export ANDROID_HOME="${ANDROID_SDK_ROOT}"
fi

if [ -z "${JAVA_HOME:-}" ] && [ -x /usr/libexec/java_home ]; then
  JAVA_HOME_CANDIDATE="$(/usr/libexec/java_home -v 17 2>/dev/null || true)"
  if [ -n "${JAVA_HOME_CANDIDATE}" ]; then
    export JAVA_HOME="${JAVA_HOME_CANDIDATE}"
  fi
fi

if ! rustup target list --installed | grep -qx 'aarch64-linux-android'; then
  rustup target add aarch64-linux-android
fi

if [ ! -f "${ZAPSTORE_CONFIG}" ]; then
  echo "Missing Zapstore config: ${ZAPSTORE_CONFIG}" >&2
  exit 1
fi

if [ ! -f "${ZAPSTORE_ENV_FILE}" ] && [ -z "${ANDROID_KEYSTORE_PATH}" ] && [ -z "${SIGN_WITH:-}" ] && [ -z "${NOSTR_KEY_PATH}" ]; then
  echo "No Zapstore signing env found. Create ${ZAPSTORE_ENV_FILE} or export the required variables first." >&2
  exit 1
fi

if [ -z "${ANDROID_KEYSTORE_PATH}" ]; then
  echo "Set ANDROID_KEYSTORE_PATH." >&2
  exit 1
fi

if [ -z "${SIGN_WITH:-}" ] && [ -z "${NOSTR_KEY_PATH}" ]; then
  echo "Set SIGN_WITH or NOSTR_KEY_PATH." >&2
  exit 1
fi

if [ -z "${SIGN_WITH:-}" ]; then
  if [ ! -f "${NOSTR_KEY_PATH}" ]; then
    echo "Missing Nostr signer file: ${NOSTR_KEY_PATH}" >&2
    exit 1
  fi
  SIGN_WITH="$(tr -d '\r\n' < "${NOSTR_KEY_PATH}")"
fi
export SIGN_WITH

if [ ! -f "${ANDROID_KEYSTORE_PATH}" ]; then
  if [ -z "${ANDROID_KEYSTORE_PASSWORD}" ] || [ -z "${ANDROID_KEY_PASSWORD}" ]; then
    echo "Set ANDROID_KEYSTORE_PASSWORD and ANDROID_KEY_PASSWORD before generating a keystore." >&2
    exit 1
  fi

  key_alias_for_generation="${ANDROID_KEY_ALIAS:-${DEFAULT_ANDROID_KEY_ALIAS}}"
  mkdir -p "$(dirname "${ANDROID_KEYSTORE_PATH}")"
  umask 077
  keytool -genkeypair \
    -alias "${key_alias_for_generation}" \
    -keyalg RSA \
    -keysize 4096 \
    -validity 9125 \
    -keystore "${ANDROID_KEYSTORE_PATH}" \
    -storetype JKS \
    -storepass "${ANDROID_KEYSTORE_PASSWORD}" \
    -keypass "${ANDROID_KEY_PASSWORD}" \
    -dname "${KEYSTORE_DNAME}"
  ANDROID_KEY_ALIAS="${key_alias_for_generation}"
fi

if [ -z "${ANDROID_KEYSTORE_PASSWORD}" ] || [ -z "${ANDROID_KEY_PASSWORD}" ]; then
  echo "Set ANDROID_KEYSTORE_PASSWORD and ANDROID_KEY_PASSWORD." >&2
  exit 1
fi

if [ -z "${ANDROID_KEY_ALIAS}" ] && [ -f "${ANDROID_KEYSTORE_PATH}" ]; then
  alias_lines="$(keytool -list -v -keystore "${ANDROID_KEYSTORE_PATH}" -storepass "${ANDROID_KEYSTORE_PASSWORD}" 2>/dev/null | sed -n 's/^Alias name: //p')"
  alias_count="$(printf '%s\n' "${alias_lines}" | sed '/^$/d' | wc -l | tr -d ' ')"
  if [ "${alias_count}" = "1" ]; then
    ANDROID_KEY_ALIAS="$(printf '%s\n' "${alias_lines}" | sed -n '1p')"
  else
    echo "Set ANDROID_KEY_ALIAS because the keystore alias could not be auto-detected." >&2
    exit 1
  fi
fi

ANDROID_KEY_ALIAS="${ANDROID_KEY_ALIAS:-${DEFAULT_ANDROID_KEY_ALIAS}}"

if [ -z "${APK_PATH}" ]; then
  cat > "${KEY_PROPERTIES_PATH}" <<EOF
storePassword=${ANDROID_KEYSTORE_PASSWORD}
keyPassword=${ANDROID_KEY_PASSWORD}
keyAlias=${ANDROID_KEY_ALIAS}
storeFile=${ANDROID_KEYSTORE_PATH}
EOF

  pnpm --store-dir "${PNPM_STORE_DIR}" --dir "${REPO_ROOT}/crates/nostr-vpn-gui" install --frozen-lockfile
  pnpm --dir "${REPO_ROOT}/crates/nostr-vpn-gui" exec tauri android build --target aarch64 --apk --ci

  APK_PATH="$(find "${ANDROID_DIR}/app/build/outputs/apk/universal/release" -maxdepth 1 -name '*.apk' -print -quit)"
fi

if [ -z "${APK_PATH}" ] || [ ! -f "${APK_PATH}" ]; then
  echo "Android release APK was not found: ${APK_PATH:-<unset>}" >&2
  exit 1
fi

TEMP_P12_DIR="$(mktemp -d "${TMPDIR:-/tmp}/nostr-vpn-zapstore-XXXXXX")"
TEMP_P12_PATH="${TEMP_P12_DIR}/signing-key.p12"
TEMP_IDENTITY_EVENT_PATH="${TEMP_P12_DIR}/identity-event.json"
keytool -importkeystore \
  -noprompt \
  -srckeystore "${ANDROID_KEYSTORE_PATH}" \
  -srcstoretype JKS \
  -srcstorepass "${ANDROID_KEYSTORE_PASSWORD}" \
  -srcalias "${ANDROID_KEY_ALIAS}" \
  -srckeypass "${ANDROID_KEY_PASSWORD}" \
  -destkeystore "${TEMP_P12_PATH}" \
  -deststoretype PKCS12 \
  -deststorepass "${ANDROID_KEYSTORE_PASSWORD}" \
  -destkeypass "${ANDROID_KEYSTORE_PASSWORD}" \
  -destalias "${ANDROID_KEY_ALIAS}"

if [ "${LINK_SIGNING_CERT}" = "1" ]; then
  KEYSTORE_PASSWORD="${ANDROID_KEYSTORE_PASSWORD}" \
    zsp identity --link-key "${TEMP_P12_PATH}" --relays "${ZAPSTORE_IDENTITY_RELAY}" --offline > "${TEMP_IDENTITY_EVENT_PATH}"
  nak event "${ZAPSTORE_IDENTITY_RELAY}" < "${TEMP_IDENTITY_EVENT_PATH}"
fi

zsp utils extract-apk "${APK_PATH}" >/dev/null

if [ "${INSTALL_ON_DEVICE}" = "1" ]; then
  adb install -r "${APK_PATH}"
  adb shell am start -n to.iris.nvpn/.MainActivity >/dev/null
fi

if [ "${CAPTURE_SCREENSHOT}" = "1" ]; then
  mkdir -p "$(dirname "${SCREENSHOT_PATH}")"
  sleep 5
  adb exec-out screencap -p > "${SCREENSHOT_PATH}"
fi

if [ "${SKIP_PUBLISH}" != "1" ]; then
  ZSP_PUBLISH_ARGS=(publish "${ZAPSTORE_CONFIG}" --channel "${ZAPSTORE_CHANNEL}")
  if [ "${ZSP_AUTO_CONFIRM}" = "1" ]; then
    ZSP_PUBLISH_ARGS+=(-y)
  fi
  if [ "${ZSP_SKIP_PREVIEW}" = "1" ]; then
    ZSP_PUBLISH_ARGS+=(--skip-preview)
  fi
  if [ -n "${ZSP_EXTRA_FLAGS}" ]; then
    IFS=' ' read -r -a ZSP_EXTRA_FLAGS_ARRAY <<< "${ZSP_EXTRA_FLAGS}"
    ZSP_PUBLISH_ARGS+=("${ZSP_EXTRA_FLAGS_ARRAY[@]}")
  fi
  zsp "${ZSP_PUBLISH_ARGS[@]}"
fi
