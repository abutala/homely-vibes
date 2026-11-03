# BLE Widget Rig

A test rig for one question that no Simulator can answer and no one should
stand at a door for: **can a Home Screen widget's tap talk Bluetooth, and
from which process and state?** It is AugustUnlock's widget shape (two
`Button(intent:)`s, the intent compiled into the app and the widget, the
tap run in the app's process) against a Bluetooth peripheral that lives on
the Mac and echoes every write back as a notification, which is the shape
of the lock's key exchange.

## Parts

- `scripts/rig_peripheral.swift` + `run_peripheral.sh` — the Mac side: a
  `CBPeripheralManager` advertising service `7E57A6B0-0001-…` with a write
  characteristic and a notify characteristic; a write is echoed 50 ms later.
  Built into a small app bundle and opened by LaunchServices, because a
  `swift` script or a bare binary has no usage description macOS accepts and
  dies at the first Bluetooth call (TCC). Lines go to `/tmp/rig-peripheral.log`.
- `BLEWidgetRig/RigProbe.swift` — the phone side: one probe = power on,
  retrieve the remembered peripheral (or scan for the service once), connect,
  discover, subscribe, write 16 random bytes, wait for the echo; every stage
  stamped in ms, the summary in `Library/Caches/rig.log`.
- `Shared/RigIntents.swift` — the two widget buttons. **Background**: the
  intent runs in the app's process in the background (`supportedModes` with
  `.foreground(.dynamic)`), which is how AugustUnlock's widget unlocks.
  **Foreground**: `openAppWhenRun`, the trade-off Tesla's widget takes; the
  app opens and the probe runs in it.
- `BLEWidgetRig/ContentView.swift` — pairs on first launch (a foreground
  scan), a button for a foreground probe from the app itself, and the log.
- `BLEWidgetRig/Info.plist` — `bluetooth-central` background mode. Remove it
  to measure the "no background mode" case.

## Run

```bash
BLEWidgetRig/scripts/run_peripheral.sh 2>&1 | tee /tmp/rig-peripheral-run.log
```

```bash
BLEWidgetRig/scripts/build_ipa.sh 2>&1 | tee /tmp/blewidgetrig-build-ipa.log
```

Sideloadly installs `build/BLEWidgetRig.ipa`. On the phone: open the app
once (it pairs; allow Bluetooth), add the **BLE Rig** widget, tap each
button, then read the log:

```bash
xcrun devicectl device copy from --device <UDID> --domain-type appDataContainer --domain-identifier com.deviationlabs.BLEWidgetRig.<TEAMID> --source Library/Caches/rig.log --destination /tmp/rig.log 2>&1 | tee /tmp/rig-copy.log
```

A line looks like `widget-background: ok in 1870 ms [powered 5 12, retrieved
13, connected 640, services 790, characteristics 905, subscribed 1010,
written 1150, echoed 16 bytes 1870]`, with the app's state at the start.

## Findings

2026-11-03, iPhone 14 Pro, iOS 27.0.1, Sideloadly: with the
`bluetooth-central` background mode, `widget-background` (app state
`background`) completed in 1981 ms, connected at 1121 ms; `widget-foreground`
in 247 ms on the link the first tap left open; the foreground pairing in
5234 ms with the permission prompt inside it. Without the mode, AugustUnlock's
key exchange had stalled at 3 s and at 6 s. Details: `AugustUnlock/Logbook.md`.
