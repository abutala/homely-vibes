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

Bluetooth needs no server either: `AugustBLEProtocol.swift` and
`AugustBLEOperation.swift` port the minimum of
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
app reads it when you pick the lock and again after any open that used the
cloud, at most once per launch. A key that August shows under
`OfflineKeys.created` is not on the lock yet. To load it (expected, not yet
verified), stand at the door, turn off WiFi and cellular so the official August
app has to use Bluetooth, and lock or unlock once with it. Until then that lock uses the cloud, with no
error shown.

## Building an IPA (for Sideloadly)

Same flow as [`NoShorts`](../NoShorts/README.md#building-an-ipa-for-sideloadly):

```bash
AugustUnlock/scripts/build_ipa.sh 2>&1 | tee /tmp/augustunlock-build-ipa.log
```

Output: `build/AugustUnlock.ipa`, unsigned — install via [Sideloadly](https://sideloadly.io).

## Home Screen widget

Long-press the Home Screen → **+** → AugustUnlock → **Doors** (small: 2 doors,
medium: up to 4). One button per lock on the account, with no lock state shown.

- A tap unlocks that door.
- A tap while that door's command is still running sends the opposite, as the
  app's button does.
- A tap within 3 minutes of that door reporting unlocked locks it. After that
  a tap unlocks again: the door may have auto-locked since.

The tap runs in the app (launched in the background if needed), not in the
widget, so it uses the app's sign-in. Only the lock picked in the app has an
offline key on the phone, so only that door tries Bluetooth; the other goes
through the cloud. The buttons read "Door 1", "Door 2" (the app's lock order)
when the widget can't read the app's lock names — see
[Logbook.md](Logbook.md#2026-10-28--home-screen-widget-for-both-doors).

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
- `AugustBLEOperation.swift` — one lock/unlock over CoreBluetooth: find the
  lock by its advertised name (the serial's first 2 and last 5 characters),
  connect, run the key exchange, send the command, wait for the lock's
  result, disconnect. It has 3 s to reach a session and 12 s from there for
  the result (yalexs-ble's own operation timeout). On any failure but a jam the lock reports — no lock in range,
  Bluetooth off or not allowed, a lost link, a rejected key, a timeout — the
  app uses the cloud instead (unlock and lock are idempotent, so a double
  send is harmless). A reported jam is shown, not retried. Later opens also
  connect straight to the peripheral remembered from the last connection,
  while the scan runs.
- `KeychainStore.swift` — thin wrapper over `SecItem*` for on-device storage
  of the August email/password, install ID, access token, selected lock ID
  and name, and that lock's offline key, slot and serial. Standard practice for a
  personal-use app — this is the same trust model the official August app
  uses.
- `ContentView.swift` — the whole UI: sign-in form → one-time verification
  code entry → the unlock screen. A single-lock account skips straight to the
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
- `AugustUnlockWidget/` — the widget extension: buttons only.
  `Shared/ToggleDoorIntent.swift` is the button's intent, built into both
  targets; it runs `DoorToggler.swift` in the app, which asks
  `WidgetTapPolicy.swift` whether to lock or unlock. `Shared/SharedLockList.swift`
  passes the lock names to the widget through the Keychain.

## Measuring lag

The screen shows how long the last lock/unlock took ("Last unlock: 1.2 s"),
after an icon for the path that carried it: a blue Bluetooth rune, or a grey
cloud. For a per-stage split, read the phone's log from a Mac with the phone
connected over USB. `log stream` reads only the Mac's own log, never the phone's, so collect
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

The Bluetooth protocol, the exit policy and the widget-tap policy have unit tests against bytes produced by yalexs-ble's
own code (`scripts/gen_ble_vectors.py` prints them: `uv run --script
AugustUnlock/scripts/gen_ble_vectors.py`). They run on the Mac, not in CI:

```bash
cd AugustUnlock && swift test 2>&1 | tee /tmp/augustunlock-swift-test.log
```

`Package.swift` exists only for these tests: it builds `AugustBLEProtocol.swift`,
`BackgroundExitPolicy.swift` and `WidgetTapPolicy.swift` alone. The app builds from `AugustUnlock.xcodeproj`.

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
