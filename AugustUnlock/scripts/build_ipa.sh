#!/bin/bash
# Build an unsigned AugustUnlock.ipa for Sideloadly.
#
# Sideloadly re-signs at install time with the user's free Apple ID, so we ship
# an unsigned .app inside Payload/ — no Apple ID or team setup required on the
# building Mac. Output: build/AugustUnlock.ipa under the repo root.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." > /dev/null && pwd)"
PROJECT="$REPO_ROOT/AugustUnlock/AugustUnlock.xcodeproj"
DERIVED="$REPO_ROOT/build/sideload"
OUT_DIR="$REPO_ROOT/build"
OUT_IPA="$OUT_DIR/AugustUnlock.ipa"

rm -rf "$DERIVED" "$OUT_DIR/Payload" "$OUT_IPA"
mkdir -p "$DERIVED" "$OUT_DIR"

xcodebuild \
  -project "$PROJECT" \
  -scheme AugustUnlock \
  -configuration Release \
  -sdk iphoneos \
  -derivedDataPath "$DERIVED" \
  -destination 'generic/platform=iOS' \
  CODE_SIGNING_ALLOWED=NO \
  CODE_SIGN_IDENTITY="" \
  CODE_SIGNING_REQUIRED=NO \
  DEVELOPMENT_TEAM="" \
  PROVISIONING_PROFILE_SPECIFIER="" \
  build 2>&1 | tee /tmp/augustunlock_build.log | tail -5

APP="$DERIVED/Build/Products/Release-iphoneos/AugustUnlock.app"
[ -d "$APP" ] || { echo "build failed: $APP not found"; exit 1; }

mkdir -p "$OUT_DIR/Payload"
cp -R "$APP" "$OUT_DIR/Payload/"
(cd "$OUT_DIR" && zip -qry AugustUnlock.ipa Payload && rm -rf Payload)

echo "IPA: $OUT_IPA ($(du -h "$OUT_IPA" | cut -f1))"
