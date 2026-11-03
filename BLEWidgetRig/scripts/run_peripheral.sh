#!/bin/bash
# Build (if needed) and launch the Mac echo peripheral for the BLE Widget Rig
# as a small app bundle, then follow its log. Stop it with: pkill rig_peripheral
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
APP="${TMPDIR:-/tmp}/rig_peripheral.app"
BIN="$APP/Contents/MacOS/rig_peripheral"
if [ ! -x "$BIN" ] || [ "$HERE/rig_peripheral.swift" -nt "$BIN" ] || [ "$HERE/rig_peripheral.plist" -nt "$BIN" ]; then
  mkdir -p "$APP/Contents/MacOS"
  cp "$HERE/rig_peripheral.plist" "$APP/Contents/Info.plist"
  swiftc -O -o "$BIN" "$HERE/rig_peripheral.swift"
  codesign -s - -f "$APP" > /dev/null
fi
pkill -x rig_peripheral 2> /dev/null || true
: > /tmp/rig-peripheral.log
open "$APP"
echo "launched $APP; log: /tmp/rig-peripheral.log"
tail -f /tmp/rig-peripheral.log
