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
handshake — open source, but porting it to CoreBluetooth is out of scope for a
one-button convenience app. The cloud API round-trip is the practical option.
*It was never measured at 1-2 s: real use shows ~5 s — see 2026-10-17. Ported
anyway on 2026-10-17 — see "Bluetooth first, cloud fallback".*

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
- *The last two bullets were replaced on 2026-09-30 by a status fetch on every
  open — see that entry — and that fetch by unlock-first on 2026-10-17.*

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

## 2026-09-22 — Switching locks mid-operation could leave the wrong door "Unlocked"

Third finding from the same review pass, on the fix commit itself: "Change
Lock" and "Sign Out" were only ever guarded by nothing — only the main
toggle button disabled itself during an in-flight operation. A lock/unlock
in flight is neither cancelled nor awaited (it's a detached `Task`), so
switching lock (or signing out) while, say, the ~60s garage-bridge unlock
was still pending would: drop the *new* lock's auto-unlock silently
(`autoUnlockIfReady`'s `operationResult == .idle` guard rejects it, nothing
retries), while the *old* lock's request eventually completes and writes
its success into the same shared `isUnlocked`/`operationResult` state the
screen is now using to describe the newly-switched-to lock — showing a
green "Unlocked" for a door that was never touched, while the door that
actually got unlocked (the old one) has silently dropped off screen with no
indication. Fixed the simple way: disable both buttons while an operation
is in flight, same as the toggle button already does. No attempt to cancel
or reconcile a stale in-flight result — not worth the complexity for a
personal one-button app; just don't let the race start. *Since 2026-09-30,
reopening the app does cancel in-flight work (see that entry); the buttons
stay disabled. Since 2026-10-12, a return from the background lets a running
operation finish instead. Since 2026-10-23, the toggle button stays enabled in
flight and cancels the command for its opposite; the other two stay disabled.*

## 2026-09-30 — Resuming from the background left the screen lying about the door

Reported from real use: background the app, come back, and the state was
wrong. Two causes, both in the optimistic `isUnlocked` design above:

1. **The belief outlived the truth.** `isUnlocked` changed only when this app
   sent a command. August's auto-lock, the keypad, or another phone changed
   the door without telling it — and the `!isUnlocked` guard then
   *suppressed* the auto-unlock on resume, showing "Unlocked — tap to lock"
   for a locked door.
2. **A request suspended with the app wedged the next open.** iOS gives a
   backgrounded app a few seconds; a ~60s bridge unlock still in flight is
   frozen and typically comes back as a lost connection. Meanwhile
   `operationResult` sat at `.inProgress`, so the resume path's
   `operationResult == .idle` guard skipped the auto-unlock entirely.

Fix: every open (cold launch, setup finishing, return from background) now
cancels whatever is in flight, fetches the lock's state from August
(`GET /locks/{id}`, `LockStatus.status` — the field
`August/august_client.py` already reads through yalexs' `LockDetail`), and
unlocks only if the lock is not already unlocked. After a lock/unlock the
screen shows the `status` from August's reply (what yalexs'
`async_unlock` returns), re-fetching if that is a value we don't recognize.
*Since 2026-10-12, a return from the background no longer cancels an
operation that is still running — see that entry. Since 2026-10-17, an open
no longer fetches the state first — it unlocks at once — and over Bluetooth
the state shown is the one requested, on the lock's success code (see
"Bluetooth first, cloud fallback").*
Cancellation alone doesn't stop a late reply from landing, so every state
write after an await is guarded by a cancellation check. The screen resets to
"State unknown" when an open starts, so a failed open never leaves the
pre-background reading on display.

Rejected: `GET /locks/{id}/status`. yalexs has it (`async_get_lock_status`),
but `august_client.py` never calls it, so nothing in this repo proves its
shape; `/locks/{id}` is the path the Python monitor already exercises.

## 2026-10-12 — Backgrounding mid-operation showed "network connection lost"

Reported from real use: tap unlock (or lock), switch apps, and the operation
failed with "The network connection was lost". iOS suspends a backgrounded app
within seconds, the ephemeral session's socket dies with it, and the reply is
lost — though August often finished the command anyway.

Fix: `run(_:)` holds a `UIApplication.beginBackgroundTask` (`BackgroundKeepAlive`)
for exactly the life of the operation, and ends it as soon as the operation
ends so the app can suspend. Resume no longer replaces an operation that is
still running; it opens afresh only when nothing is in flight. If iOS takes the
time back first (about 30s; a slow bridge can take ~60s), the expiration
handler cancels the operation and marks the screen idle, so the next open
unlocks again.

Rejected: a background `URLSession`. It outlives suspension, but it is
delegate-based upload/download only, so every call would have to leave
`async data(for:)` — too much for one button.

## 2026-10-17 — ~5 s to unlock; the official app takes ~1 s

Reported from real use. Each open made two serial cloud calls: `GET
/locks/{id}` for the state, then the sync `PUT /remoteoperate/{id}/unlock`,
which answers only after August relays the command to the lock and the bolt
moves. The official August app is fast because, near the door, it talks to the
lock over Bluetooth and skips the cloud entirely.

Reviewed adversarially (prosecution, defense, refute) before any code. Shipped:

1. **Unlock first.** The open path sends the unlock at once; the GET is gone.
   Unlocking an unlocked door is a no-op, and the reply's `status` is the real
   state (cloud only; over Bluetooth the lock sends a success code, see
   "Bluetooth first, cloud fallback"). Trade-off, accepted: opening the app to *lock* an unlocked door now
   waits for a redundant unlock before the button works.
2. **Timing.** Every request logs its wall time (`os.Logger`, subsystem
   `AugustUnlock`); the screen shows the last command's total. Nothing had
   been measured before — the original "1-2 seconds" estimate (#21) was a
   guess.

Rejected, with the evidence:

- **Wake the lock on every open** (`/remoteoperate/{id}/status?...&intent=wakeup`,
  which Home Assistant sends at startup). yalexs `manager/ratelimit.py` allows
  one per 26 minutes and warns the server may block the client permanently.
- **`&connection=persistent`** ("hyper bridge"). yalexs adds it only to the
  `type=async` URLs, never the sync unlock; untested here, so not shipped blind.
- **Async op** (`type=async`). The bolt does not move sooner; the result
  arrives over PubNub, a new dependency.
- **HomeKit.** Irrelevant: the 1 s baseline is the August app over Bluetooth.

Next, if the timings show the PUT alone is still ~4 s: the cloud path cannot
reach 1 s, and the only route left is the Bluetooth port above.
*Measured, then ported — see the next entry.*

## 2026-10-17 — Bluetooth first, cloud fallback

The timings from the entry above, read off the phone's log: `PUT
/remoteoperate/{id}/unlock -> 200 in 8955 ms` cold, then `PUT .../lock -> 200
in 4608 ms` eight seconds later, warm. No 401, no extra GET. Both are the
bridge-connected lock, the only one with a loaded offline key: ~4.6 s warm,
~9 s cold, and up to ~60 s (see 2026-09-22). The cloud cannot get near the official app's ~1 s, so the app now
talks Bluetooth near the door: `AugustBLEProtocol.swift` (wire format) and
`AugustBLEOperation.swift` (CoreBluetooth), a minimum port of yalexs-ble.

**Go/no-go first.** Bluetooth needs an offline key the lock already holds. A
read-only check of `GET /locks/{id}` on a real two-lock account: one lock had a
key under `OfflineKeys.loaded` (16 bytes and a slot), the other had one only
under `OfflineKeys.created` — made by August, never loaded onto the lock.
yalexs reads only `loaded[0]`; the lock rejects a key it does not hold. So the
port reads only `loaded`, and a lock without one uses the cloud with no error.
Expected, not yet seen: the official app loads a created key the next time it
talks Bluetooth to the lock.

What the port keeps from yalexs-ble, each for a reason found in its source:

1. **One cipher context per direction for the whole connection.** The command
   channel is AES-CBC with a zero IV, and the chain runs across frames.
   Re-creating the CommonCrypto context per frame restarts the chain, and every
   frame after the first decrypts to garbage on the lock.
2. **Every plain frame goes through the decryptor**, an unsolicited status push
   included, because the lock's chain advances per frame it sends. A frame that
   is not 18 bytes is refused *before* the decryptor: a partial block stays
   buffered and garbles every later frame.
3. **Secure notify before plain notify**, then the key exchange, then plain
   notify (yalexs `connect`: "Order matters").
4. **A 0.25 s cooldown after the last frame before the command.** yalexs: a
   lock sent commands too fast can crash and need a battery pull.
5. **A reported jam is final.** Result codes 0x1E-0x23 are motor faults; the
   app shows them and does not retry through the cloud. Any other failure
   (no lock in range, link lost, timeout) falls back to the cloud, which is
   safe because unlock and lock are idempotent.

Skipped from yalexs-ble: the status read before a command (the cloud path
dropped it too, above), connection retries, status pushes, settings, keypad
codes, and the activity log.

**Test vectors.** yalexs-ble has frame tests but no crypto vectors, so the
expected bytes come from `scripts/gen_ble_vectors.py`, which runs yalexs-ble
6.1.0's own `Session` and `SecureSession` classes (test key 00..0f, slot 4) for
both handshake commands, the session key, three chained commands, and an ack
plus op-response encrypted by an independent AES encryptor as the lock would.
6.1.0, not the newest 7.2.2, because the repo's `uv` setting refuses releases
newer than a week; the protocol code (`secure_session.py`, `set_key`, `build_command`,
the checksums, `_setup_session`) is identical between the two.

**Default MainActor isolation.** The Xcode project sets
`SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor`, so every type is MainActor unless
marked otherwise. CoreBluetooth calls the delegate on the operation's own
queue, so the Bluetooth types are `nonisolated`; without that the build warned
that the delegate conformance "is an error in the Swift 6 language mode".

**Door test (2026-10-18), bridge-connected lock.** It worked, including
while its WiFi bridge was in place, and the user reported the rest of the
test plan as good. The one timing line that survived:
`BLE lock -> ok in 3179 ms (found -, connected 1293, session 1740, written
1998, done 3179)`. No scan was needed (the remembered peripheral connected),
the command reached the lock at ~2.0 s, and the bolt finished at ~3.2 s.
Over the cloud the same lock took 4608 ms warm and 8955 ms cold.

**Second door test, same lock**, with every line kept at `.notice`:

| Path | Line |
|---|---|
| Bluetooth, unlock | `BLE unlock -> ok in 2747 ms (found -, connected 1001, session 1302, written 1563, done 2747)` |
| Bluetooth miss, ~20 ft from the door | `BLE lock failed in 3175 ms: Bluetooth setup timed out while connecting; using the cloud` |
| Cloud fallback | `PUT /remoteoperate/<id>/lock -> 200 in 24706 ms` |

The screen showed ~28 s for that lock: the 3.2 s Bluetooth miss plus the
24.7 s PUT. The `GET /locks/{id}` key re-read that followed (276 ms) runs
after the result, in an unawaited task, and adds nothing to it. So over the
cloud this lock has taken 4.6 s, 9.0 s and 24.7 s; over Bluetooth 2.7 s and
3.2 s. Connects that succeeded took 1.0–1.3 s, and the miss failed cleanly at
the 3 s limit, so the budget stays.

Only one line survived because the timing lines were logged at `.info`, which
iOS keeps in a shared in-memory buffer that a busy phone overwrites in
seconds: one run of four Bluetooth unlocks and four locks left a single
`AugustUnlock` line in an archive that covered the whole run. They are
`.notice` now, which persists. Still
unmeasured: an open that needs a scan (`found` set). Until one is, the 3 s
setup budget stays: this run reached its session at 1740 ms without a scan,
so anything under ~2 s risks sending opens at the door to the cloud.

**The icon** is the Bluetooth rune, drawn here as a template SVG in
`Assets.xcassets` — SF Symbols has no Bluetooth mark (it is the Bluetooth
SIG's trademark).

## 2026-10-18 — Quit after 5 minutes in the background

Asked for: the app terminates itself when backgrounded for more than 5 minutes
(`BackgroundExitPolicy.defaultTimeout`, the one constant); foregrounding sooner
cancels it; an operation in flight finishes first.

Non-obvious: iOS suspends a backgrounded app within seconds (the 2026-10-12
entry), and a suspended process runs no timers. A `Task.sleep` for 5 minutes
therefore almost never fires on its own. So the check is the timestamp
comparison on return to the foreground (`exit(0)` if the deadline passed),
with the timer as a best effort for the cases where iOS keeps the process
awake. The visible cost: reopening after more than 5 minutes flashes the app
and closes it; the next launch is a clean cold start that unlocks as usual.

An in-flight operation postpones the exit: the timer and `run(_:)` both ask
again when it ends, so the background task from the 2026-10-12 fix is never
cut short. The policy is a pure struct that takes `Date` as a parameter; its
tests run with `swift test` (it is in `Package.swift`).

## 2026-10-23 — A tap while in flight cancels and sends the opposite

Asked for: a tap during "Unlocking…" switches to locking at once (the app had
auto-unlocked on open when you wanted it locked), and the unlock must not
happen. So the tap cancels the in-flight command and sends the opposite. It
does not queue behind it: a queued lock lets the door unlock first.

Non-obvious: cancelling means different things on the two paths.

| Path | What the cancel stops | What can still happen |
|---|---|---|
| Bluetooth | Drops the link (`AugustBLEOperation.cancel`). Before the command write (~2 s in), the lock never gets the command | After the write, the lock unlocks and then locks: the next command needs a new link, so the order holds |
| Cloud | Drops the phone's HTTP request (`URLSession` stops with the task) | August's server may already hold the unlock, and a bridge lock can take ~60 s (2026-09-22 entry). It can reach the lock after the lock command, and the screen shows "Locked" over an open door |

The cloud case is a known gap. A queue closed it, but the door then unlocked
on every switch. Also, the tap writes the new command to the screen
at once, before its task starts: a fast second tap reads the command now
shown, not the cancelled one.

## 2026-10-28 — Home Screen widget for both doors

Asked for: a widget with both doors, tap to unlock and tap again to override,
coloured circles, state shown, and never opening the app. It took four probe
builds on the phone to find why no tap ever ran. The two findings that cost a day:

1. **`.buttonStyle(.plain)` makes a widget button inert on this phone.** A
   tap on it falls through to the widget body: the renderer logs "Launching
   with no widgetURL" and SpringBoard opens the app ("source: Widget"); no
   intent process runs at all. Every circle build used `.plain`, so every tap
   opened the app and the app's open-unlock moved the picked door — which
   read as "the widget ignores which button I pressed". `.borderedProminent`
   runs the intent in the widget, in the background, as documented. Proven
   with two buttons side by side (A bordered, B plain): A logged `perform`,
   B did nothing. Not the cause, each ruled out by a probe: a `LiveActivityIntent`
   (its "run in the app" route never fired either), an intent `@Parameter`
   (the archive log said `Prepared slot to Int(nil)`, but a parameterless
   intent on a `.plain` button was just as dead), Sideloadly's signing (`linkd`
   indexed both `Metadata.appintents`, the extension launched, no crash log).
2. **The widget can read the app's Keychain, with no entitlement.**
   Sideloadly signs both with keychain-access-groups `TEAMID.*`, so the
   widget reads what the app writes in its default group (the widget read the
   app's access token in every probe). The earlier "no shared group" result
   (commit `203c18d`) named an explicit group neither binary was entitled to;
   that was the bug, not Sideloadly. An App Group is still unavailable.

## 2026-10-30 — The widget PR broke the app; the widget is now a separate island

PR #54 shipped the widget and, in the same PR, rewrote the app around it:
`ContentView`'s state machine moved into a new `DoorController`, the
`AugustClient` and `KeychainStore` the app used moved to `Shared/` and
changed for the widget, and the app's door name came from a hard-coded slot
table. On the phone: the door names were swapped, commands timed out and
Bluetooth was rarely used, and "Change Lock" looked broken. Each phone test
checked the widget; none re-checked the app's own open → unlock → change-lock
flow.

The causes found in the code:

- **Names by slot.** `Doors.swift` named the locks "Front door" (slot 1) and
  "Garage" (slot 0) by their place in the ID-sorted list. A mid-PR commit
  flipped the slots, judged from taps that finding 1 above was still
  misrouting. The label was wrong in the app, so after "Change Lock" the
  circle kept the other door's name, and the widget's buttons acted on the
  wrong door.
- **A 30 s deadline over Bluetooth plus cloud.** Bluetooth setup (3 s) and
  the op (12 s) came before a cloud fallback that a WiFi bridge can take
  ~60 s for; the old app had no deadline.
- **Keychain writes changed under the app.** `set` went from delete-and-add
  to `SecItemUpdate`, and any result other than "not found" returned
  silently, so a failed write left the old value (a likely stale offline key).

Fix: the app is restored file for file to `c69bce9`, before the widget. The
widget shares no code or state with it:

- `WidgetCloud` reads the app's access token from the Keychain and never
  writes anything there. On a 401 the widget shows "Open the app to sign in"
  under the doors; the app refreshes the token on its next request.
- The widget fetches the lock list itself and names each door as August
  does. The label and the command read the same list entry by position, with
  no table between them; only a change to the account's lock list can move a
  lock, and the widget redraws with it. Its own lock list and door records
  live in the extension's UserDefaults.
- A second tap while a command runs doesn't cancel it. The newer tap owns the
  door's record, and the older reply is dropped instead of overwriting it.
- Cloud only, 20 s deadline (widget work is reported to get about 20–25 s
  before iOS stops it; Apple documents no limit). A run older than 45 s
  reads as unknown, and an "unlocked" older than 3 minutes as unknown.

Rule: a widget, extension or second surface gets its own files. Changing
the app's code for it is a separate PR, re-tested on the phone through the
app's own flows.

## 2026-11-01 — A command could hold the screen until the phone woke

Reported: the app sits in "Unlocking…" and never recovers (seen with the
phone possibly in Low Power Mode), and "Change Lock" is dead meanwhile.

Cause, from the code (TRIAL of the fix, 2026-11-01): the Bluetooth timers
run on `DispatchTime`, device uptime, which stops while the phone sleeps. A
command stalled at screen-off keeps its remaining 3 s or 12 s until wake,
then the cloud fallback runs for up to ~60 s. Above all that there was no
deadline, and the resume path skipped open-unlock while a command was in
flight, so the screen stayed stuck until the chain ended. Low Power Mode was
never shown to matter; sleep alone explains it. "Change Lock" and "Sign Out"
were `.disabled` during a command by design.

Fix: `CommandDeadline` (pure, tested) — 30 s per command, raced with a
`Task.sleep` on the continuous clock, and checked again by wall clock when
the app returns to the foreground, in case the sleep did not fire on wake.
A timed-out command ends as "Timed out — tap to retry" with the state
unknown, and no automatic unlock follows: after a timeout the next command
is the user's (a stale unlock could undo a lock they tapped). 30 s is Amit's
call, knowing a bridge lock's ~60 s cloud reply is then lost; the door may
still move. Change Lock and Sign Out cancel the command; the lock picker says
the previous command may still complete, since a cloud request August
already holds cannot be recalled. The offline-key refresh, an unstructured
task that outlives a cancelled command, now writes nothing once the lock
changed or the account signed out.

Not measured: whether a `Task.sleep` past due fires at once when the app
thaws. Test: start a command, lock the phone for 90 s, unlock; the screen
must show the timeout within a few seconds of wake.

**Same day, on the phone (d7e1580):** the front door "cycled" four times.
The phone log shows why: Bluetooth worked for two taps, then failed to
connect, and every command went to the cloud (1–24 s). Each tap during a
running command sent the opposite (the 2026-10-23 feature) and "cancelled"
the cloud request, which August ran anyway: unlock, lock, unlock, lock. The
deadline never fired. Amit's call: switching stays (drop the previous
where Bluetooth allows, add the new one otherwise); only a repeat is
dropped. So a second tap within 0.75 s sends nothing. The status text stays
as it was: the cloud-phase mechanics live here, not on the screen. Also
seen: the garage's bridge answered `HTTP 560` after 24 s.

**Same day, after the TRIAL:** the command logic left `ContentView` for a
pure `CommandMachine`, built to mirror `formal/august_unlock_command.qnt`
action for action, so the model's three pinned properties have a Swift
test each plus a seeded random walk with simulated Bluetooth and cloud. The
first model found a hole in itself, not in the app (formal/Logbook.md,
2026-11-01); the Swift side was then written against the corrected model.
Rule from Amit the same day: formal model and local tests first, the phone
only confirms.

**Same day, on the Simulator:** `ContentView` now talks to August through a
protocol, so a UI test can launch the app against a scripted `FakeAugust`
and watch the screens (`UITests/AppFlowTests.swift`). The six flows passed
first time, except for one wrong assertion in the test (a 1 s reply is
settled before the first wait). Nothing about the command machine changed:
the Simulator confirmed the model, which is the order Amit asked for.
The PR's reviewer then found a hole the model cannot see, because phase is
a view concern: the return to the foreground sent an unlock from the sign-in
screen too (the old `openUnlock()` guard was lost in the refactor). The
Simulator test caught it before the fix ("2 sent" after sign-in), and
`resume` now runs only on the unlock screen.

## 2026-11-01 — The widget is two unlock buttons, nothing more

On the phone both widget buttons acted on the lock the app had picked: the
taps were not reaching the buttons and opened the app instead, whose
open-unlock then ran. The toggle logic on top could also send LOCK from a
stale "unlocked" record. Amit's call: stateless buttons that only unlock.
Gone: `DoorRecord`, `DoorDisplay`, the per-door records and their tests,
the lock command. Kept: the widget's own cloud client, the lock list from
August, the 20 s tap deadline, bordered buttons (`.plain` is inert here).

**Testing the widget on the Simulator (same day).** A UI test
(`UITests/WidgetTapTests.swift`) adds the widget through SpringBoard and taps
it. On the Simulator the tap opens the app, for a reason the Simulator's own
log names: at archive time the widget process logs
`[appintents:Metadata] Failed to fetch metadata for <intent>` and `linkd`
logs `Unable to get teamId from <widget>`. The registry identifies a widget
by its signing team; Simulator builds are signed "to run locally" with no
team. Tried and ruled out: an entitlements file with `application-identifier`
and `team-identifier` (the app then refuses to launch; a widget with them in
its signature refuses to spawn), re-signing with this Mac's team
certificate (same), `-allowProvisioningUpdates` (Xcode emits only
`application-identifier`; `linkd` still wants the team). An intent name that
shares a word with the module name (`UnlockFirstDoorIntent` in
`AugustUnlockWidget`) gets a word-substituted mangled name in the metadata
(`18AugustUnlockWidget0B15FirstDoorIntentV`); renamed to `Open…` to keep the
metadata plain, though that was not the cause. So: the Simulator proves the
layout (two buttons before any lock list, the caption) and the tap stays an
expected failure there; the dispatch is proven only on the phone, where
Sideloadly's signature carries the team.

## 2026-11-02 — The widget's buttons run again: built up from Apple's sample

A day of probes (intents compiled into both targets per Apple's doc, then the
widget built under the app's module name so both bundles register the same
type) changed nothing on the phone: every tap still opened the app. A TRIAL
showed why the probes could not work: the widget-only builds of 2026-11-01
had already failed, so neither change was the cause; and the "metadata
lookup failed" diagnosis was the Simulator's error read into the phone,
whose `linkd` lines are identical for a working widget (Notes). The phone's
live syslog (`uvx pymobiledevice3 syslog live`, Info level, no sudo) shows
only that the tap was not claimed by any button: WidgetRenderer logs
`Launching with no widgetURL`, no intent runner starts.

Amit's rule, same day (memory `apple_sample_first_not_reverse_engineering`):
start from Apple's own sample and build simple to difficult. The ladder, one
Sideloadly install each, the observation a line in the widget's own log
(`Library/Caches/widget.log`, read with `xcrun devicectl device copy from
--domain-type appDataContainer --domain-identifier <widget bundle id>`):

- **A — Apple's button, verbatim shape** from [Adding interactivity to
  widgets and Live Activities](https://developer.apple.com/documentation/widgetkit/adding-interactivity-to-widgets-and-live-activities):
  `Button(intent: PingIntent()) { Image(systemName: "bolt.fill") }` in an
  `HStack` with `.tint(.white).padding()`, default button style, the intent
  in both targets, `perform()` only logs. Two taps, two `ping` lines, app
  closed. So Sideloadly's signature, iOS 27.0.1 and the free team all
  dispatch intents; the cause was in our view.
- **B** — the same shape with `OpenFirstDoorIntent`/`OpenSecondDoorIntent`
  and the real unlock behind them: `tap position=0`, `tap position=1`,
  `unlock position=0 ok`, `unlock position=1 failed: Timed out` (the garage
  bridge's cloud slowness; the stateless button simply tries again).
- **C** — the intended look on that shape: a 34 pt lock icon as the button
  label, the door name under it, each door its half, system background.
  Amit: "all operations are correct".
- **D** — `.invalidatableContent()` on the icon inside the button, Apple's
  cue that a tap is running. **The taps opened the app again.** That is the
  cause, found by the ladder: a button whose label carries
  `.invalidatableContent()` is inert under this install, and every failing
  build since 2026-10-30 had exactly that (the label `VStack` with
  `.invalidatableContent()` inside `Button(intent:)`), while the 2026-10-28
  A/B probe and Apple's sample did not. Apple's article puts the modifier on
  the views that *receive updated data*, never on the button.
- **E** — the modifier moved to the door name under the button (a sibling,
  outside it); the step-A `PingIntent` scaffold removed. Shipped: the app
  stays closed, both doors unlock (`tap position=1` … `unlock position=1 ok`
  in the widget log), and the name dims while the tap runs.

Learnings, for the next widget:

1. A system feature that misbehaves gets Apple's sample first, as-is, then
   our pieces one per build. The sample found the baseline in one install;
   the probes found nothing in ten. And the ladder's last rung named the
   cause as a by-product: one modifier, in a place Apple's sample never puts
   it.
2. The widget's own log file is the only reliable observation of a tap: the
   system log looks the same for a live and an inert button up to the moment
   of the tap, and the archive keeps no Info-level lines.
3. The phone's system log without sudo: `uvx pymobiledevice3 syslog collect`
   (the archive, Default level) and `syslog live` (Info and Debug). Cabled;
   no tunnel needed.
4. The Simulator dispatches widget intents after all. With the cue off the
   button, the UI test's tap ran `OpenFirstDoorIntent.perform()` on the
   iPhone 17 Pro Simulator (its log: `perform() finished`, `Successfully ran
   action`), ad-hoc signature and all; `linkd`'s "Unable to get teamId"
   lines come after, from the donation, and are harmless. The 2026-10-30
   and 2026-11-01 claims that the Simulator cannot run a tap were this
   same bug seen on the Simulator. `WidgetTapTests` is strict now, and the
   rung-by-rung ladder could have run there: FV + Simulator first holds.
5. Sideloadly sometimes opens with "Apple Silicon" selected as the device;
   it refuses that install (Patreon-only), so nothing lands on the Mac, but
   the phone must be re-selected by hand before Start.

## 2026-11-02 — One door blinks, the result shows, and a widget tap goes over Bluetooth

Amit, after the widget shipped: a tap dimmed both doors, nothing said
whether it worked, and the widget used only the cloud. A scoped TRIAL on the
design (`.foreground(.dynamic)` in `supportedModes`, a kept Bluetooth link,
a timeline written from the tap) found two blockers before any code, both
settled by one-rung Simulator probes:

1. **A widget intent can run in the app's process.** Apple's article lists
   `openAppWhenRun` and four protocols as what moves it there;
   `ForegroundContinuableIntent` is deprecated in favour of `supportedModes`.
   Measured: `supportedModes = [.background, .foreground(.dynamic)]` ran
   `perform()` in the `AugustUnlock` process; `[.background]` alone kept it
   in the extension. With the app quit, the tap launched it in the
   background, `perform()` ran, and the screen's `onAppear` never fired: no
   open-unlock, no exit timer, no window. The app never comes forward
   because nothing calls `continueInForeground`. So the widget's tap now
   uses the app's `AugustClient`: Bluetooth first when the lock has a loaded
   key, the cloud otherwise. The widget's own cloud unlock is gone.
2. **The widget cannot read the app's `UserDefaults`** (no App Group under
   free signing), so the per-door state (`DoorState`: which door runs, its
   last result and when) goes through the Keychain, the store the widget's
   sign-in read already crosses. On the Simulator the two bundles share the
   Keychain only with a `keychain-access-groups` entitlement on both targets
   (without it the widget read `errSecItemNotFound`; with it, the item).
   Sideloadly's re-sign ignores the file (the IPA is built unsigned) and
   gives both bundles the same default group, which is how the token read
   already works on the phone.

The rest followed the verdict and the PR's reviewers: one `OpenDoorIntent`
whose parameters are the door's position and the lock ID the widget shows,
so a tap opens the door under the finger whatever lock list the app holds
(the app keeps no list of its own for this); per-lock offline keys (one
Keychain map by lock ID, refreshed for every lock the account lists) so the
second door is not cloud-only; one `CommandGate` so the screen and a widget tap in the
same process never open two Bluetooth links to a lock; the tap's own 20 s
deadline; `.invalidatableContent()` gone — it dims every marked view for any
tap, which was the "both doors blink". The tap writes `running` and reloads
the widget's timeline, runs, writes the result and reloads again; the
provider adds one entry per clearing moment (a result at its 4 s hold, a
tap at its 30 s limit in case its process died), each door on its own
time.

**First phone run (2026-11-03, 00:30 UTC): "feels like a regression."**
Three causes, none visible on the Simulator (no Bluetooth, no August cloud):

1. The per-lock key map was empty: it fills when the app lists locks, and
   the old single-lock key (three Keychain items) was not read. So the app's
   own button and the widget both went to the cloud. Fixed: the three items
   are read as the map until the first refresh rewrites it.
2. The two `reloadTimelines` at the tap's start never rendered: the widget
   log has no timeline between the tap (00:30:32) and its end (00:30:57),
   then two. WidgetKit defers a reload asked for by the app while that
   widget's intent runs. So "Unlocking…" on one door is not possible this
   way; the cue during a tap is `.invalidatableContent()` again, which dims
   both names. The result after the tap is per door, as asked.
3. The garage's cloud unlock took 21.1 s (200) against the tap's 20 s
   deadline, so the widget said "Failed" for an unlock that happened; a
   second tap on the same door waited at the gate and timed out too. The
   deadline is 25 s, and a tap on a door still running is ignored.

Nothing above is in the 2026-11-02 learnings' Simulator-first rule's
favour or against it: the Simulator proved the mechanism and the phone
proved the data. Both runs were needed.

**Second run (00:40 UTC):** Bluetooth first, as intended, and the first
logged timeout next to a lock: `BLE unlock failed in 3197 ms: Bluetooth
setup timed out while exchanging keys; using the cloud`, then the cloud in
19.9 s and "Unlocked" on the widget. The link connected; the key exchange
did not finish within the 3 s setup budget, which was measured in the
foreground app (session at 1.3–1.7 s). A background process gets slower
Bluetooth from iOS (longer connection intervals), and the fallback costs
~20 s, so a widget tap now gives Bluetooth setup 8 s; the screen keeps
3 s. One sample; the next taps' stage timings in `app.log` say whether
8 s is enough or the stall is the lock's. Measured on the
Simulator: the tapped door shows "Failed" (no sign-in there) and clears;
the other door does not move; the seven app flows still pass.

Also new: `Library/Caches/app.log` in the app, every timing line, readable
with `devicectl` like the widget's log, because the Bluetooth failures
Amit sees next to the lock have never reached a log archive. The kept
Bluetooth session between commands (the "interrupt, then lock" case) is
PR B, after this log shows what those failures look like; yalexs-ble keeps
its link 5.1 s after a command and the lock drops an idle link at 30 s, so
that window is seconds, not the 30 s the design first said.
