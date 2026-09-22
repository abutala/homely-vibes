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

## 2026-09-22 — Two auth bugs the original build never caught, because it was never run

The PR that introduced `AugustUnlock` (#21) shipped without ever running the
app — only CLT was available on the building machine, not full Xcode. Once
actually built and signed for a real device, sign-in was completely broken,
in two separate ways, both in `requestSession()`:

1. **`vInstallId`/`vPassword` are JSON booleans, not strings.** The original
   code cast `json["vInstallId"] as? String`, which always fails against a
   real August response (confirmed via a captured `/session` response:
   `"vInstallId": true, "vPassword": true`, not string values) — so the cast
   silently returned `nil`, and `requestSession()` always reported "not
   authenticated." Concretely: right after entering the correct emailed 2FA
   code, `validateCode()` re-ran `requestSession()`, got the same false
   negative, and threw "enter verification code" again — an unbreakable
   loop. No amount of code review catches a silent `as?` cast failure; it
   compiles clean and only misbehaves against the real API shape.
2. **The `/session` `identifier` field needs `"<login_method>:"` prefixed.**
   `yalexs`' `AuthenticatorAsync` builds it as
   `self._login_method + ":" + self._username` (e.g. `"email:you@x.com"`),
   not the bare email. The original code sent the bare email, which August
   rejects as a malformed identifier — surfaced identically to a bad
   password. Symptom: "incorrect August email or password" in the app, while
   the same credentials worked fine in a browser. This is the same class of
   bug as #1 — a detail that's undocumented outside `yalexs`' source and
   invisible without a real login attempt.

Both fixes were found the same way: build a case, then read the exact
`yalexs` code path August/august_client.py already exercises successfully
(`authenticator_common.py::_authentication_from_session_response`,
`authenticator_async.py::async_authenticate`) and diff it against the Swift
port line by line. **Lesson: for an API with no public docs, "matches the
proven-working Python client" isn't optional polish — it's the only source
of truth, and it has to be checked field-by-field including types, not just
endpoint paths.**

## 2026-09-22 — Multi-lock accounts: no silent lowest-ID pick

The original design picked whichever lock had the lexicographically lowest
ID and used it forever, on the theory that "single-lock household" covers
the common case. It doesn't here: confirmed on a real multi-lock account
(front door + garage), the app silently controlled the wrong door on first
run. Replaced with: `fetchLocks()` returns everything, the caller decides —
auto-select on a single-lock account (unchanged zero-tap behavior), a
one-time picker when there's more than one, plus a "Change Lock" link on the
main screen so a wrong pick doesn't require signing all the way out to fix.

## 2026-09-22 — A bridge-connected lock can take ~60s; that's not a hang

The garage lock (behind a WiFi bridge, unlike the directly-connected front
door) spun for the better part of a minute before succeeding. Checked
`yalexs` before assuming a bug: `ApiAsync` uses a 60s `command_timeout` for
exactly this operation, and has dedicated exceptions for "the bridge
(connect) is offline / is in use / failed to respond" — August's own client
expects a bridge relay to legitimately take that long. Nothing to fix;
documented in the README so it doesn't read as broken next time.

## 2026-09-22 — Auto-unlock on app open (deliberate trade-off, not a default)

Changed from "tap a button to unlock" to "opening the app unlocks
immediately, tap again to lock" — requested explicitly, not a design
decision made unilaterally. Flagged the trade-off before building it: this
means an accidental app open (pocket touch, a curious kid swiping through
apps) unlocks the front door with zero confirmation. Accepted knowingly.
Implementation notes:

- Fires from both `.onAppear` (cold launch) and `scenePhase` transitioning
  `.background -> .active` (resuming from background) — `.onAppear` alone
  only fires once per view lifetime and misses "reopen from background,"
  which is the common case in practice. See the next entry for why it must
  check the *old* phase too, not just `newPhase == .active`.
- Guarded on the door's local `isUnlocked` state so reopening an
  already-unlocked session doesn't resend the command every time you glance
  at the phone.
- The door's lock/unlock state is optimistic and session-local (whatever the
  last command issued was) — there's no status poll, so a lock operated by
  someone else (the physical keypad, another household member's app) won't
  be reflected until this app issues its own command.

## 2026-09-22 — Two bugs in the auto-unlock feature, caught by PR review before merge

The automated PR reviewer (`agent-review.yml`) flagged both on the PR that
added auto-unlock, before it merged:

1. **`scenePhase == .active` fires on more than "reopened from
   background."** Control Center, Notification Center, and the
   incoming-call banner all bounce the scene `.active -> .inactive ->
   .active` without ever passing through `.background`. The original guard
   (`if newPhase == .active`) re-fired the auto-unlock on every one of
   those — including right after the user deliberately locked the door via
   the button, silently undoing it. First fix attempt (`oldPhase ==
   .background && newPhase == .active` in the same `onChange` call) was
   itself wrong — a real background resume is `.background -> .inactive ->
   .active`, two separate `onChange` calls, so that exact single-step
   pairing never occurs and the fix made *all* auto-unlock-on-resume dead
   code (caught by a second review pass on the fix itself). Landed on:
   track having actually seen `.background` in a flag, consume it on the
   next `.active`. That's the only version that both ignores transient
   interruptions and still fires on a genuine resume.
2. **Auto-unlock never actually fired the first time.** `submitLogin`,
   `submitCode`, and the lock-picker's selection all set `phase = .ready`
   directly; `autoUnlockIfReady()` only ran from `.onAppear` and the
   `scenePhase` handler, neither of which fires when setup finishes while
   the app is already in the foreground. So the very case the feature was
   built for — finish signing in, expect the door to already be open — did
   nothing until the *next* cold launch or background resume. Fixed by
   routing every "setup just finished" transition through one
   `enterReady()` helper that sets the phase and fires the auto-unlock.

Neither would have been caught by the local build-and-run testing this PR
otherwise did — the first only reproduces via a real interruption (a call,
Control Center) at just the right moment; the second only reproduces on a
device that isn't already signed in, which the testing device wasn't by the
time auto-unlock was added. **Lesson: a device smoke test proves the happy
path works; it doesn't substitute for reasoning through every path that
sets the same state.**
