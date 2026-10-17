# AugustUnlock

Gotchas, incidents and error reference: [Logbook.md](Logbook.md).

A one-button iOS app: open it, your August door unlocks — no tap needed, opening
the app *is* the confirmation. Tap the button again to lock back up. No home
server, no VPN — the app talks to August's cloud API directly, the same API the
official August app uses when it is out of Bluetooth range, so it works from
anywhere with a network connection (WiFi or cellular), not just at home. Near
the door the official app is faster (~1 s vs ~5 s) because it uses Bluetooth.

## Why no server

There's no maintained Swift/iOS SDK for August/Yale locks, official or
community. Rather than run a middleman server on a home host (extra
infrastructure, an extra hop of latency, one more thing that can be down when
you're standing at the door), `AugustClient.swift` talks to
`api-production.august.com` directly — a small, plain REST client mirroring
the request shapes already proven out in [`August/august_client.py`](../August/august_client.py)
(this repo's Python August integration, built on the `yalexs` library).

Real BLE (Bluetooth) control was considered too, since it avoids the cloud
round-trip. It's not worth it for a personal project yet: August has never
published a public BLE SDK, and the community reverse-engineered protocol
(`yalexs-ble`, used by Home Assistant) is Python-only with no Swift port —
porting its encrypted offline-key handshake to CoreBluetooth is a large job.

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

## Building an IPA (for Sideloadly)

Same flow as [`NoShorts`](../NoShorts/README.md#building-an-ipa-for-sideloadly):

```bash
AugustUnlock/scripts/build_ipa.sh 2>&1 | tee /tmp/augustunlock-build-ipa.log
```

Output: `build/AugustUnlock.ipa`, unsigned — install via [Sideloadly](https://sideloadly.io).

## How it works

- `AugustClient.swift` — the whole August cloud client: login, email 2FA,
  token refresh, lock discovery, lock status, lock/unlock. See its header comments and
  [Logbook.md](Logbook.md) for the two non-obvious API details (a revoked API
  key, and lock operations using a different key than login). A lock
  connected through a WiFi bridge (e.g. a detached garage) can take up to
  ~60s to respond if the bridge is slow to relay the command — this is
  August's own client behavior, not a bug here.
- `KeychainStore.swift` — thin wrapper over `SecItem*` for on-device storage
  of the August email/password, install ID, access token, and selected lock
  ID. Standard practice for a personal-use app — this is the same trust model
  the official August app uses.
- `ContentView.swift` — the whole UI: sign-in form → one-time verification
  code entry → the unlock screen. A single-lock account skips straight to the
  button; a multi-lock account gets a one-time picker on first sign-in (and a
  "Change Lock" link on the main screen to redo it later). Every open — cold
  launch or back from the background — sends the unlock at once, with no
  status check first (an already-unlocked door just stays unlocked). A
  lock/unlock still running when the app is backgrounded keeps running and
  reports its own result instead. The
  state shown after each command is what the lock reported back, not what was
  requested, so a door that auto-locked or was operated elsewhere is picked
  up the next time the app opens.

## Measuring lag

The screen shows how long the last lock/unlock took ("Last unlock: 4.8 s"),
from the command to August's reply. For a per-request split, stream the
device log from the Mac while the phone is connected:

```bash
log stream --predicate 'subsystem == "AugustUnlock"' 2>&1 | tee /tmp/augustunlock-timing.log
```

Each request logs a line like `PUT /remoteoperate/<id>/unlock -> 200 in 4612 ms`.

## Security notes

- **Opening the app unlocks the door — there is no confirmation tap.** This
  is a deliberate convenience trade-off: an accidental app open (pocket
  touch, a curious kid) unlocks the door with no further action. Tap the
  button to lock back up.
- Your August email and password live in this device's Keychain only. They
  are sent to `api-production.august.com` over HTTPS and nowhere else.
- If you ever want to revoke access, change your August account password —
  every cached session (this app's included) stops working immediately.
