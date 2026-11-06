# AugustUnlock

Gotchas, incidents and error reference: [Logbook.md](Logbook.md).

A one-button iOS app: open it, your August door unlocks — no tap needed, opening
the app *is* the confirmation. Tap the button again to lock back up. A tap
while it is still unlocking cancels the unlock and locks instead (and the other
way round while locking). No home server, no VPN. Near the door the app talks to the lock over Bluetooth, as the
official August app does; anywhere else, or for a lock with no offline key, it
uses August's cloud API directly, so it works from anywhere with a network
connection (WiFi or cellular), not just at home.

## Why no server

There's no maintained Swift/iOS SDK for August/Yale locks, official or
community. Rather than run a middleman server on a home host (extra
infrastructure, an extra hop of latency, one more thing that can be down when
you're standing at the door), `AugustClient.swift` talks to
`api-production.august.com` directly — a small, plain REST client mirroring
the request shapes already proven out in [`August/august_client.py`](../August/august_client.py)
(this repo's Python August integration, built on the `yalexs` library).

Bluetooth needs no server either: `AugustBLEProtocol.swift`,
`AugustBLEEngine.swift` and `AugustBLELink.swift` port the minimum of
[`yalexs-ble`](https://github.com/Yale-Libs/yalexs-ble) (the community
protocol Home Assistant uses) to CoreBluetooth. See
[How it works](#how-it-works).

## Setup

1. **Install Xcode 26.4+** from the App Store and sign in (Xcode → Settings →
   Accounts). This is what lets Xcode auto-download the on-device Developer
   Disk Image — without it, device deploys fail with "Developer disk image
   could not be mounted".
2. **Enable Developer Mode on the iPhone**: Settings → Privacy & Security →
   Developer Mode → On → reboot → confirm.
3. Open `AugustUnlock.xcodeproj` in Xcode.
4. Select your team under **Signing & Capabilities** → your Apple ID. Xcode
   rewrites `DEVELOPMENT_TEAM` in `project.pbxproj` automatically — verify
   with `grep DEVELOPMENT_TEAM AugustUnlock.xcodeproj/project.pbxproj` and
   commit the change.
5. Connect your iPhone, select it as the run destination, **Cmd+R**.
6. On first launch, sign in with your August email + password. If August asks
   for a verification code, it's emailed (not texted) — enter it once. After
   that the app stays signed in like the official app does; you should never
   need to sign in again on that phone. If your account has more than one
   lock, you'll get a one-time picker — see [How it works](#how-it-works).
   The moment setup finishes, the app unlocks (see
   [Security notes](#security-notes)) — that's expected, not a bug.
7. On the first open after the app has read a lock's offline key (see
   below), iOS asks for Bluetooth access. Allow it, or every open uses the
   cloud. A lock with no offline key never asks.

## Bluetooth needs an offline key

The Bluetooth path works only for a lock that holds an *offline key* for your
account. August lists it on `GET /locks/{id}` under `OfflineKeys.loaded`; the
app reads it for every lock on the account when it lists them, when you pick
a lock, and again after any open that used the cloud, at most once per launch
per lock, so the widget's doors can go over Bluetooth too. A key that August shows under
`OfflineKeys.created` is not on the lock yet. To load it (expected, not yet
verified), stand at the door, turn off WiFi and cellular so the official August
app has to use Bluetooth, and lock or unlock once with it. Until then that lock uses the cloud, with no
error shown.

## Building an IPA (for Sideloadly)

Same flow as [`NoShorts`](../NoShorts/README.md#building-an-ipa-for-sideloadly):

```bash
AugustUnlock/scripts/build_ipa.sh 2>&1 | tee /tmp/augustunlock-build-ipa.log
```

The build's date, time and commit show in small print at the bottom of the
app's screen (`BUILD_STAMP`, set by the script into Info.plist; an Xcode build
shows none). Output: `build/AugustUnlock.ipa`, unsigned — install via [Sideloadly](https://sideloadly.io)
(`open -a Sideloadly build/AugustUnlock.ipa`, then **Start**). Never install with Xcode or
`devicectl`: they use the plain bundle ID, so the phone ends up with a second copy and a second
Keychain (a second August sign-in).

## Home Screen widget

Long-press the Home Screen → **+** → AugustUnlock → **Doors**. One size, full
width: an unlock button per lock, named as August names it, in lock-ID
order. A tap sends unlock for that door and nothing else: the widget shows
no state and never locks (unlock is a no-op on an unlocked door, so a
repeat is harmless). Each door's whole half is its button. The tapped
door's name reads "Unlocking…" the moment you tap (the button is a toggle,
which WidgetKit redraws at once; the other door does not move); when the
tap ends it says "Unlocked", "Failed" or "No reply" for about twelve seconds,
then the name again. "No reply" means the cloud request went out and the
tap ran out of time before August answered; August may still open the
door. A second tap on a door still unlocking does nothing, though its cue
may flicker until the result. Each tap runs in the app's own process in
the background (the app never comes forward), so it takes the same path as
the app's button: Bluetooth when the lock has a loaded key (~1–3 s), the
cloud otherwise or when Bluetooth fails (the screen allows it 1–25 s; a
widget tap, what is left of its 28 s). The sign-in line under
the doors, when shown, is a link that opens the app. A whole tap has 28 s: iOS ends a background intent at about
30 s, and a tap ended that way shows nothing. Bluetooth gets 6 s to set
up, the cloud gets what is left. With both doors tapped, the first door's
result draws when the second door's tap ends, if its hold has not passed
by then: WidgetKit redraws the widget only once no tap of its runs. A tap on a locked phone (the Today view
before Face ID) does nothing at all, by iOS's rule for widget buttons.
"Open the app to sign in" under the buttons means August rejected the
sign-in; opening the app renews it.

## How it works

- `AugustClient.swift` — the whole August cloud client: login, email 2FA,
  token refresh, lock discovery, lock status, lock/unlock. See its header comments and
  [Logbook.md](Logbook.md) for the two non-obvious API details (a revoked API
  key, and lock operations using a different key than login). A lock
  connected through a WiFi bridge (e.g. a detached garage) can take up to
  ~60s to respond if the bridge is slow to relay the command — this is
  August's own client behavior, not a bug here.
- `AugustBLEProtocol.swift` — the Bluetooth wire format, with no
  CoreBluetooth: 18-byte frames, both checksums, the AES-128 ciphers, and the
  two-step key exchange. Step 1 is AES-ECB under the offline key; the session
  key is 8 random bytes of ours plus 8 from the lock; the command channel is
  AES-CBC with a zero IV whose chain runs across frames, so each direction
  keeps one CommonCrypto context for the whole connection.
- `AugustBLEEngine.swift` — the Bluetooth path as a pure state machine, no
  CoreBluetooth: connect, discover, key exchange, the command, the ack and
  the result, and the link's life after it. A link stays open 5 s after a
  command for the app's own next tap (the "tap while unlocking, to lock
  instead" case rides the same link, with no connect and no key exchange);
  a cancelled command that was already written runs to its result on the
  link, unreported, and the next command follows it. The link closes on a
  timeout, a failed write, link loss, Bluetooth off, the app going to the
  background, or a widget tap (its process is in the background and a kept
  link would block the official app). `swift test` drives it through the
  real handshake and commands with yalexs-ble's own wires.
- `AugustBLELink.swift` — the CoreBluetooth side of one lock's link, one
  per lock for the process: it turns every callback into an engine input
  with the time, runs the engine's outputs and arms its timers. The
  screen's command has 12 s to reach a session (a connect took 9.4 s
  while the Wi-Fi bridge held the lock; `CommandDeadline` keeps the sum
  inside the 30 s deadline) and 6 s from there for the result; a widget
  tap has 6 s and 12 s. On any failure but a
  jam the lock reports — no lock in range, Bluetooth off or not allowed, a
  lost link, a rejected key, a timeout — the app uses the cloud instead
  (unlock and lock are idempotent, so a double send is harmless). A
  reported jam is shown, not retried. Later opens connect straight to the
  peripheral remembered from the last connection, while the scan runs.
- `KeychainStore.swift` — thin wrapper over `SecItem*` for on-device storage
  of the August email/password, install ID, access token, selected lock ID
  and name, the offline key, slot and serial of every lock on the account
  (one map by lock ID), and the widget's per-door tap state. Standard practice for a
  personal-use app — this is the same trust model the official August app
  uses.
- `CommandMachine.swift` — the command state machine as a pure value: what a
  tap, an open, a return to the foreground, a reply or the deadline does. It
  mirrors the Quint model [formal/august_unlock_command.qnt](../formal/august_unlock_command.qnt),
  and its tests include a seeded random walk with simulated Bluetooth and
  cloud replies, naps and returns.
- `AugustService.swift` — the protocol `ContentView` talks to (`August.shared`):
  `AugustClient` on a device, or `FakeAugust` when the launch environment sets
  `AUGUST_FAKE=1` or a launch left that marker (`TestHooks`). The fake is scripted by `AUGUST_FAKE_SIGNED_IN`,
  `AUGUST_FAKE_REPLY_SECONDS`, `AUGUST_FAKE_PATH` and `AUGUST_FAKE_FAIL`, and
  counts the commands it got (the timing caption shows "N sent").
- `ContentView.swift` — the whole UI: sign-in form → one-time verification
  code entry → the unlock screen. It feeds `CommandMachine` the events and
  runs the effects it returns (start a command, cancel one). A single-lock account skips straight to the
  button; a multi-lock account gets a one-time picker on first sign-in (and a
  "Change Lock" link on the main screen to redo it later). Every open — cold
  launch or back from the background — sends the unlock at once, with no
  status check first (an already-unlocked door just stays unlocked). A
  lock/unlock still running when the app is backgrounded keeps running and
  reports its own result instead. After a cloud command the state shown is
  what the lock reported back, not what was requested; over Bluetooth the
  lock answers with a success code, so the state shown is the one requested.
  Either way, a door that auto-locked or was operated elsewhere is picked up
  the next time the app opens.

## Deadline and recovery

Every lock/unlock has 30 s to answer. Past that the circle goes gray with
"Timed out — tap to retry"; the command's late reply is discarded, though a
cloud request August already holds may still move the door (a WiFi-bridge
lock can take ~60 s — that reply is lost). A command that stalled while the
phone slept is caught the same way when the app returns to the foreground,
and the app does not unlock again by itself after a timeout. "Change Lock"
and "Sign Out" stay live during a command: both cancel it, and the picker
says the previous command may still complete.

A tap while a command runs sends the opposite. While the command is still
on Bluetooth, a cancel before the write drops it; once it has gone to the
cloud, August runs the request it already holds, so the lock does both in
turn. A second tap within 0.75 s is the same tap and sends nothing.

## Measuring lag

The screen shows how long the last lock/unlock took ("Last unlock: 1.2 s"),
after an icon for the path that carried it: a blue Bluetooth rune, or a grey
cloud. Every timing line (each cloud request, each Bluetooth attempt with
its stages, each widget tap) is also in the app's own file,
`Library/Caches/app.log` (last 200 lines), which the phone keeps. A widget
tap writes `widget intent position=N` first, from the app's process; a tap
on the widget's body writes `opened by the widget body`; a tap with
neither line never reached the widget (a locked phone):

```bash
xcrun devicectl device copy from --device <UDID> --domain-type appDataContainer --domain-identifier com.deviationlabs.AugustUnlock.<TEAMID> --source Library/Caches/app.log --destination /tmp/august-app.log 2>&1 | tee /tmp/augustunlock-app-log.log
```

The same lines go to the system log; to read them with the rest of the
phone's log, read the phone's log from a Mac with the phone connected over USB. `log stream` reads only the Mac's own log, never the phone's, so collect
an archive from the phone, then read it:

```bash
sudo log collect --device-udid <UDID> --last 30m --output /tmp/phone.logarchive 2>&1 | tee /tmp/augustunlock-log-collect.log
```

```bash
log show /tmp/phone.logarchive --predicate 'subsystem == "AugustUnlock"' 2>&1 | tee /tmp/augustunlock-timing.log
```

`<UDID>` is the phone's identifier (`xcrun devicectl list devices`). The app
logs at `.notice`, which the phone keeps on disk; widen `--last` for an older
test. Lines look like this (the first from a real door test; `found -` means
the remembered peripheral connected without a scan):

- `BLE lock -> ok in 3179 ms (found -, connected 1293, session 1740, written 1998, done 3179)`
- `BLE unlock failed in 3004 ms: Bluetooth setup timed out while searching for the lock; using the cloud`
- `PUT /remoteoperate/<id>/unlock -> 200 in 4612 ms`

## Tests

The app quits itself after 5 minutes in the background (`BackgroundExitPolicy.swift`).

The Bluetooth protocol and engine, the exit policy, the command machine, the command gate, the widget's door names and door state have unit
tests; the protocol's run against bytes produced by yalexs-ble's own code (`scripts/gen_ble_vectors.py` prints them: `uv run --script
AugustUnlock/scripts/gen_ble_vectors.py`). They run on the Mac, not in CI:

```bash
cd AugustUnlock && swift test 2>&1 | tee /tmp/augustunlock-swift-test.log
```

The widget has a UI test on the Simulator (`UITests/WidgetTapTests.swift`):
it adds the Doors widget through SpringBoard's gallery and checks the two
buttons and the sign-in caption, then taps a button with the app quit and
checks that the tapped door reads "Unlocking…" at once and alone (the tap
is slowed 5 s with `AUGUST_SLOW_WIDGET_TAP=1` on the app's launch, a marker
the tap's background launch reads), then its result, holds it and clears
it, that the app stays closed, and that a tap on the sign-in line under
the doors opens it. The tap lands near the corner of the door's half, where
only the body was before 2026-11-05. The tap runs in the app's process
(Logbook 2026-11-02) against `FakeAugust` (`AUGUST_FAKE=1` leaves a marker
the background launch reads), so the result is "Unlocked" after the
fake's one-second reply. The Simulator has no Bluetooth and no August cloud:
the key carry-over, the cloud's timing and the phone's reload deferral
(Logbook 2026-11-03) were all found on the phone. The widget
reads the tap's state from the Keychain, which the Simulator shares between
the two bundles only through the `keychain-access-groups` entitlement both
targets carry (Sideloadly ignores it and gives both the same group anyway).
The app declares the `bluetooth-central` background mode (`Info.plist`,
merged into the generated one): without it a backgrounded app gets no
Bluetooth events, so a widget tap's key exchange stalled (Logbook
2026-11-03).
On the phone the proof is `app.log` above and the widget's own log,
`Library/Caches/widget.log` in the widget's data container.

```bash
xcodebuild test -project AugustUnlock/AugustUnlock.xcodeproj -scheme AugustUnlockUITests -destination 'platform=iOS Simulator,name=iPhone 17 Pro' -allowProvisioningUpdates 2>&1 | tee /tmp/augustunlock-uitest.log
```

`Package.swift` exists only for these tests: it builds the pure files alone
(`AugustBLEProtocol.swift`, `AugustBLEEngine.swift`, `BackgroundExitPolicy.swift`,
`CommandDeadline.swift`, `CommandMachine.swift`, `CommandGate.swift`, `AugustBLETiming.swift`,
`AugustUnlockWidget/DoorNames.swift`, `Shared/DoorState.swift`, `Shared/Deadline.swift`). The command machine's properties are also pinned by
`make formal` (see [formal/README.md](../formal/README.md)). The app builds from `AugustUnlock.xcodeproj`.

The same properties run through the real screens on the Simulator against
`FakeAugust` (`UITests/AppFlowTests.swift`): open-unlock, a tap while pending,
the double-tap dedup, Change Lock mid-command, the 30 s timeout, and no
auto-unlock on the return after a stall. About two minutes; the Simulator
boots on its own:

```bash
xcodebuild test -project AugustUnlock/AugustUnlock.xcodeproj -scheme AugustUnlockUITests -destination 'platform=iOS Simulator,name=iPhone 17 Pro' -only-testing:AugustUnlockUITests/AppFlowTests 2>&1 | tee /tmp/augustunlock-appflow.log
```

## Security notes

- **Opening the app unlocks the door — there is no confirmation tap.** This
  is a deliberate convenience trade-off: an accidental app open (pocket
  touch, a curious kid) unlocks the door with no further action. Tap the
  button to lock back up.
- Your August email and password live in this device's Keychain only. They
  are sent to `api-production.august.com` over HTTPS and nowhere else.
- The lock's offline key, read from August's API over HTTPS, also lives in
  the Keychain. Anyone with it can operate that lock from Bluetooth range, so
  treat it like the password. It is never sent anywhere: it only encrypts the
  first step of the key exchange with the lock.
- If you ever want to revoke access, change your August account password —
  every cached session (this app's included) stops working immediately. That
  does not touch the offline key already on the phone: a lost phone keeps
  Bluetooth access until that key is replaced on the lock. Removing the
  account from the lock in the official August app should do that; it is
  not tested here.
