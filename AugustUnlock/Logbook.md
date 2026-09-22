# AugustUnlock Logbook

Dated incidents, landmines, and rejected options. Usage lives in [README.md](README.md).

## 2026-09-21 — Two non-obvious facts about August's API, ported from August/august_client.py

`AugustClient.swift` is a from-scratch REST client (no Swift SDK exists for
August/Yale locks), built by reading `august_client.py` and the `yalexs`
library it wraps rather than the public API docs, because two things there
aren't documented anywhere public:

1. **The API key `yalexs` ships by default for password-auth calls is
   revoked.** POSTing `/session` with it returns `403 {"code":"Forbidden",
   "message":"API key is not valid"}`. `august_client.py`'s
   `apply_working_api_key()` already found and documented the working legacy
   key (`7cab4bbd-...`) — `AugustClient.swift` uses that same key for
   `/session`, `/validation/email`, `/validate/email`.
2. **Lock operations use a different API key than login**, even though both
   hit the same host (`api-production.august.com`) and reuse the same access
   token. `yalexs` calls this a different "brand" (`YALE_AUGUST` vs `AUGUST`)
   internally, but there's no real OAuth handshake involved — the access
   token from the `AUGUST`-brand `/session` call is simply reused as-is
   against `YALE_AUGUST`-brand endpoints (`/users/locks/mine`,
   `/remoteoperate/{lock_id}/unlock`) with their own key
   (`66814fd9-...`).

If August rotates either key again, the fix is the same shape as
`august_client.py`'s: find the new working key (check that Python client
first — it's actively used and monitored) and update the two `private static
let ...APIKey` constants in `AugustClient.swift`.

## Rejected: home-server middleman

Considered running a small FastAPI endpoint on a home host that holds the
August session and exposes an authenticated `/unlock` — the app would just
POST to it. Rejected: no home host in this setup already runs a web server,
it adds a network hop (and a single point of failure — the door doesn't open
if that host is down), and reaching it from outside the house needs a VPN or
tunnel that doesn't exist yet either. Talking to August's cloud directly has
none of that, at the cost of the app itself holding the August password in
Keychain — an acceptable trade for a personal-use app (see README's Security
notes).

## Rejected: Bluetooth (BLE) control

August/Yale never published a public BLE SDK. The community reverse-engineered
protocol (`yalexs-ble`, used by Home Assistant for local control) is
Python-only, with no Swift port, and implements an encrypted offline-key
handshake that isn't publicly documented — porting it from scratch is out of
scope for a one-button convenience app. The cloud API round-trip is the
practical option; it's typically 1-2 seconds.
