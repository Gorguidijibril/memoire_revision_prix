#!/usr/bin/env bash
set -euo pipefail

BUNDLE_DIR=".bcis-wave0/bundle"
ARCHIVE=".bcis-wave0/bundle.reassembled.tar.gz"
PART_GLOB=".bcis-wave0/bundle.part*.b64"

rm -rf "$BUNDLE_DIR" "$ARCHIVE"
mkdir -p "$BUNDLE_DIR"

# Concatenate short connector-safe base64 fragments, removing line endings.
cat $PART_GLOB | tr -d '\r\n' | base64 -d > "$ARCHIVE"

gzip -t "$ARCHIVE"
tar -tzf "$ARCHIVE" >/dev/null
tar -xzf "$ARCHIVE" -C "$BUNDLE_DIR"

echo "BCIS_BUNDLE_REASSEMBLY_PASS $(sha256sum "$ARCHIVE" | awk '{print $1}')"

node .bcis-wave0/runner.mjs
exec node .bcis-wave0/hold.mjs
