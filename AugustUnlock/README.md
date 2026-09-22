# AugustUnlock

Gotchas, incidents and error reference: [Logbook.md](Logbook.md).

A one-button iOS app: tap it, your August front door unlocks. No home server, no
VPN — the app talks to August's cloud API directly, the same way the official
August app does, so it works from anywhere with a network connection (WiFi or
cellular), not just at home.

## Why no server

There's no maintained Swift/iOS SDK for August/Yale locks, official or
community. Rather than run a middleman server on a home host (extra
infrastructure, an extra hop of latency, one more thing that can be down when
you're standing at the door), `AugustClient.swift` talks to
`api-production.august.com` directly — a small, plain REST client mirroring
the request shapes already proven out in [`August/august_client.py`](../August/august_client.py)
(this repo's Python August integration, built on the `yalexs` library).

Real BLE (Bluetooth) control was considered too, since it avoids the cloud
round-trip. There's no viable path for a personal project: August has never
published a public BLE SDK, and the community reverse-engineered protocol
(`yalexs-ble`, used by Home Assistant) is Python-only with no Swift port —
porting it means reverse-engineering an encrypted offline-key handshake from
scratch.

## Setup

1. **Install Xcode 16+** from the App Store and sign in (Xcode → Settings →
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
   need to sign in again on that phone.

## Building an IPA (for Sideloadly)

Same flow as [`NoShorts`](../NoShorts/README.md#building-an-ipa-for-sideloadly):

```bash
AugustUnlock/scripts/build_ipa.sh 2>&1 | tee /tmp/augustunlock-build-ipa.log
```

Output: `build/AugustUnlock.ipa`, unsigned — install via [Sideloadly](https://sideloadly.io).

## How it works

- `AugustClient.swift` — the whole August cloud client: login, email 2FA,
  token refresh, lock discovery, unlock. See its header comments and
  [Logbook.md](Logbook.md) for the two non-obvious API details (a revoked API
  key, and lock operations using a different key than login).
- `KeychainStore.swift` — thin wrapper over `SecItem*` for on-device storage
  of the August email/password, install ID, access token, and discovered lock
  ID. Standard practice for a personal-use app — this is the same trust model
  the official August app uses.
- `ContentView.swift` — the whole UI: sign-in form → one-time verification
  code entry → the unlock button. No settings screen; the first lock found on
  the account is used automatically.

## Security notes

- Your August email and password live in this device's Keychain only. They
  are sent to `api-production.august.com` over HTTPS and nowhere else.
- If you ever want to revoke access, change your August account password —
  every cached session (this app's included) stops working immediately.
