#!/bin/bash
# Compiles launcher.applescript into a double-clickable app that opens one host in
# Screen Sharing, full screen. Settings come from the environment; see ../README.md.
set -euo pipefail

: "${HOST:?Set HOST to the remote Mac, e.g. HOST=mac-mini.local}"
NAME="${NAME:-ScreenShare}"
SCALE="${SCALE:-on}"
DEST="${DEST:-$HOME/Desktop}"

# HOST is pasted into AppleScript source, so allow hostname characters only.
[[ "$HOST" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "HOST must be a hostname or IP: $HOST" >&2; exit 1; }
[[ "$NAME" =~ ^[A-Za-z0-9\ _-]+$ ]] || { echo "NAME may hold letters, digits, space, _ and - only" >&2; exit 1; }
case "$SCALE" in
  on) scale_bool=true ;;
  off) scale_bool=false ;;
  *) echo "SCALE must be on or off: $SCALE" >&2; exit 1 ;;
esac

src="$(cd "$(dirname "$0")/.." && pwd)/launcher.applescript"
tmp="$(mktemp "${TMPDIR:-/tmp}/screenshare.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
sed -e "s/__HOST__/$HOST/" -e "s/__SCALE__/$scale_bool/" "$src" > "$tmp"

app="$DEST/$NAME.app"
rm -rf "$app"
osacompile -o "$app" "$tmp"
echo "Built $app (host $HOST, scaling $SCALE)"
