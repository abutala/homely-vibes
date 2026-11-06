#!/bin/bash
# Builds MergeQueueBar in release mode and wraps it into MergeQueueBar.app.
# With --install, copies the app to /Applications and (re)launches it.
set -euo pipefail

cd "$(dirname "$0")/.."

APP_NAME="MergeQueueBar"
APP_DIR="$APP_NAME.app"
BUNDLE_ID="com.deviationlabs.$APP_NAME"

swift build -c release

rm -rf "$APP_DIR"
mkdir -p "$APP_DIR/Contents/MacOS"
cp ".build/release/$APP_NAME" "$APP_DIR/Contents/MacOS/$APP_NAME"

cat > "$APP_DIR/Contents/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>$APP_NAME</string>
    <key>CFBundleIdentifier</key>
    <string>$BUNDLE_ID</string>
    <key>CFBundleName</key>
    <string>$APP_NAME</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>LSUIElement</key>
    <true/>
    <key>LSMinimumSystemVersion</key>
    <string>13.0</string>
</dict>
</plist>
EOF

# Ad-hoc signing is enough: the app reads no Keychain item itself (gh does).
codesign --force --sign - --identifier "$BUNDLE_ID" "$APP_DIR"
echo "Built $APP_DIR"

if [[ "${1:-}" == "--install" ]]; then
    pkill -x "$APP_NAME" || true
    rm -rf "/Applications/$APP_DIR"
    cp -R "$APP_DIR" /Applications/
    open "/Applications/$APP_DIR"
    echo "Installed and launched /Applications/$APP_DIR"
fi
