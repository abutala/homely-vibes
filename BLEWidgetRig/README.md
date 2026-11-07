# BLE Widget Rig

A test rig for one question that no Simulator can answer and no one should
stand at a door for: **can a Home Screen widget's tap talk Bluetooth, and
from which process and state?** It is AugustUnlock's widget shape (three
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
- `Shared/RigIntents.swift` — the three widget buttons. **Background**: the
  intent runs in the app's process in the background (`supportedModes` with
  `.foreground(.dynamic)`), which is how AugustUnlock's widget unlocks.
  **Foreground**: `openAppWhenRun`, the trade-off Tesla's widget takes; the
  app opens and the probe runs in it. **Detached**: the intent returns at
  once and the probe runs detached under a background task (the section
  "Detached tap measurement" below).
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

## Detached tap measurement

The question behind "progress on the widget while a tap runs" (AugustUnlock
PR #71's Logbook entry): WidgetKit defers every reload until the tap's intent returns,
so a stage can only be drawn if `perform()` returns at once and the unlock
runs detached. Apple exempts reloads from the widget's budget only while
the widget performs an intent, so a reload asked after the return may run
late, and the process's life after the return is unknown. The **Detached**
button measures both: its `perform()` writes the tap's start for the widget
(`RigMark`, the Keychain), begins a background task, starts the work
detached and returns. The detached work logs once a second for 40 s how
long the process still runs and what `backgroundTimeRemaining` says, runs
the Bluetooth echo at once, and asks a widget reload at 2 s, 6 s and 12 s.
The widget's provider logs every run with its lag after the tap
(`rig-widget.log`) and draws the same on the widget ("run 15:23:41.2 · tap
+3.1 s").

Steps, with the rig installed and paired:

1. Start the Mac peripheral: `BLEWidgetRig/scripts/run_peripheral.sh`.
2. With the phone unlocked, tap **Detached** three times, a minute apart.
   Watch the caption under the buttons: it shows when the widget was last
   drawn and how long after the tap.
3. Lock the phone, swipe to the Today view, tap **Detached** once there.
4. Copy both logs:

```bash
xcrun devicectl device copy from --device <UDID> --domain-type appDataContainer --domain-identifier com.deviationlabs.BLEWidgetRig.<TEAMID> --source Library/Caches/rig.log --destination /tmp/rig.log 2>&1 | tee /tmp/rig-copy.log
```

```bash
xcrun devicectl device copy from --device <UDID> --domain-type appDataContainer --domain-identifier com.deviationlabs.BLEWidgetRig.<TEAMID>.Widget --source Library/Caches/rig-widget.log --destination /tmp/rig-widget.log 2>&1 | tee /tmp/rig-widget-copy.log
```

The widget's bundle id under Sideloadly's re-sign is the pattern AugustUnlock's
widget uses; `xcrun devicectl device info apps --device <UDID>` lists the
exact one.

What decides the design, per tap: `rig.log` says when `perform()` returned,
how many `+N s alive` lines followed (the process's life; 25 or more means
the unlock fits), whether the background task expired, and whether
`detached-echo` ended `ok`; `rig-widget.log` says when each of the three
asked reloads ran (within about 3 s of being asked means a stage can show).
The locked tap says whether a locked phone runs the intent at all.

## Findings

See `AugustUnlock/Logbook.md`: 2026-11-03 (a widget tap over Bluetooth),
2026-11-05 (the hit area) and 2026-11-06 (the Detached measurement: one
redraw after the return, the process suspended at ~30 s, a locked phone
inert).
