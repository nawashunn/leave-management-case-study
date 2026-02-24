#!/bin/sh
set -eu

CERT_PFX_PATH="${TLS_CERT_PATH:-/etc/nginx/certs/lms.example.local.pfx}"
CERT_OUT_PATH="/tmp/lms.example.local.crt"
KEY_OUT_PATH="/tmp/lms.example.local.key"

if [ ! -f "$CERT_PFX_PATH" ]; then
  echo "TLS bootstrap error: PFX file not found at $CERT_PFX_PATH"
  exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
  apk add --no-cache openssl >/dev/null
fi

PFX_PASSWORD="${TLS_CERT_PASSWORD-}"
PASSIN_ARG="pass:${PFX_PASSWORD}"

extract_pfx() {
  LEGACY_FLAG="$1"
  openssl pkcs12 $LEGACY_FLAG -in "$CERT_PFX_PATH" -clcerts -nokeys -out "$CERT_OUT_PATH" -passin "$PASSIN_ARG" &&
    openssl pkcs12 $LEGACY_FLAG -in "$CERT_PFX_PATH" -nocerts -nodes -out "$KEY_OUT_PATH" -passin "$PASSIN_ARG"
}

if ! extract_pfx ""; then
  if ! extract_pfx "-legacy"; then
    echo "TLS bootstrap error: failed to extract cert/key from PFX. Set TLS_CERT_PASSWORD in .env and verify the password is correct."
    exit 1
  fi
fi

chmod 600 "$KEY_OUT_PATH"
