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
   deadline became 25 s (one 28 s limit for the whole tap since
   2026-11-05), and a tap on a door still running is ignored.

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
~20 s, so a widget tap now gives Bluetooth setup 6 s; the screen kept
3 s (12 s since 2026-11-03). The cloud leg got its own 25 s deadline from
the moment it started, so the Bluetooth attempt never ate the cloud's time
(a reviewer's catch: 8 + 20 did not fit one 25 s deadline; one 28 s limit
for the whole tap replaced it on 2026-11-05). One sample; the next taps' stage
timings in `app.log` say whether 6 s is enough or the stall is the lock's. Measured on the
Simulator: the tapped door shows "Failed" (no sign-in there) and clears;
the other door does not move; the seven app flows still pass.

Also new: `Library/Caches/app.log` in the app, every timing line, readable
with `devicectl` like the widget's log, because the Bluetooth failures
Amit sees next to the lock have never reached a log archive. The kept
Bluetooth session between commands (the "interrupt, then lock" case) is
PR B, after this log shows what those failures look like; yalexs-ble keeps
its link 5.1 s after a command and the lock drops an idle link at 30 s, so
that window is seconds, not the 30 s the design first said.

**Third run (01:04 UTC), and Amit: "no dude."** Bluetooth from the widget
still stalled in the key exchange, now at 6.4 s; the cloud took 7.9 s. No
outcome was seen on the widget, and both names blinked. Three answers:

1. **The stall is iOS, not the radio budget.** Apple, [Core Bluetooth
   Background Processing](https://developer.apple.com/library/archive/documentation/NetworkingInternetWeb/Conceptual/CoreBluetooth_concepts/CoreBluetoothBackgroundProcessingForIOSApps/PerformingTasksWhileYourAppIsInTheBackground.html):
   an app without a Core Bluetooth background mode is "unable to perform
   Bluetooth-related tasks, nor is it aware of any Bluetooth-related
   events" while not in the foreground; the events queue until it comes
   forward. The connect is done by the system, which is why "connected"
   looked fine; the key exchange needs the delegate, which never fired.
   The TRIAL's P4 said this; I logged it as "partial" and tried budgets.
   The app now declares `UIBackgroundModes = bluetooth-central`, which
   wakes the app for `CBCentralManagerDelegate`/`CBPeripheralDelegate`
   calls. Phone-only to prove; the Simulator has no radio.
2. **The outcome was drawn too late to be seen.** WidgetKit draws a reload
   some seconds after it is asked for; a 4 s hold measured from the write
   was over before the draw. The hold is 12 s.
3. **Both names blinked** because I put `.invalidatableContent()` back
   after the per-door redraw proved impossible mid-tap. Amit: no. There was
   no cue during a tap after that (the toggle brought one back on
   2026-11-03); the outcome after it was the feedback.

## 2026-11-03 — PR B: the tapped door blinks by itself, and the Bluetooth link outlives a command

Amit's scope, one PR: the widget's pressed button alone blinks, a status
after it, each button its own lock, Bluetooth in the widget, and Bluetooth
that survives a "tap while unlocking, to lock instead". PR #62 had the last
three; a scoped TRIAL (`scratchpad/trial5`) then found two things before
any code:

1. **Only a `Toggle` can blink one door.** WidgetKit cannot redraw a widget
   while its intent runs, so a `Button` has no per-door cue; Apple:
   "`Toggle` updates its appearance optimistically and indicates its new
   state immediately — without waiting for the result of the performed
   action." Each door is now `Toggle(isOn: mark == .running, intent:)`
   with a custom `ToggleStyle` (the icon; "Unlocking…" while on). Proven on
   the Simulator with a slowed tap (`AUGUST_SLOW_WIDGET_TAP`, a marker file
   the tap's background launch can read): "Unlocking…" on the tapped door
   1.3 s after the tap, the other door still, then the result, then the
   name. Known wart: a second tap on a running door flips the cue off until
   the reload; the tap itself is ignored.
2. **A link kept only until the next cancel helps nobody.** The first
   design dropped the link on a cancel after the write; the write lands
   1.2–1.5 s after a tap on a cold link and the screen's override comes at
   0.75 s or later, so the interrupt case would have rebuilt the link every
   time. Now a cancelled command that was written runs to its result on the
   link, unreported, and the opposite follows on the same link after a 1 s
   gap (yalexs never sends the opposite that fast; the gap stays until ten
   fast pairs at the door say it can go). A cancel before the write drops
   only the command.

The Bluetooth path is two files now. `AugustBLEEngine` is a pure state
machine: inputs are the radio's events and the timers, each with the time;
outputs are writes, notifies, timers and completions. Sixteen `swift test`
scenarios drive it through the real handshake and commands with the wires
`gen_ble_vectors.py` prints from yalexs-ble's own classes (extended for the
init reply, a status push and a second command on the same chain): the
interrupt, a cancel in the cooldown, a push between commands, a skipped
push (CBC garbles one frame, then recovers, as yalexs says), the keep
timer against a late command, the close race, the background, link loss,
Bluetooth off, a jam, stale timers. `AugustBLELink` is the CoreBluetooth
adapter, one per lock for the process; `AugustBLEOperation` is gone. The
old single-link teardown lives on as the engine's `closing` state.

Rules the TRIAL pinned: a command's budgets start when it reaches the head
of the link's queue; every timer carries the command's token or the link's
epoch; "in background" is engine state (a command that ends there closes
the link; the widget's process starts in it; the screen's `.background`
closes idle links inside a background task); the widget's tap never keeps
a link, since a kept link blocks the official app; the lock's own idle
drop is 30 s, far past the 5 s keep.

Maintainability, same PR (Amit: "we've churned this app a lot"): one
`KeychainStore` in `Shared/` for the app, the widget and the door state
(three readers before); one `LineLog` for `app.log` and `widget.log` (two
copies before); the screen's background keep-alive and the link's share
`BackgroundTask`.

**The door run (03:57 UTC).** The kept link works: after an unlock over
Bluetooth, the lock command was written 214 ms after it started and done
at 2263 ms, with no connect and no key exchange (`BLE lock -> ok in 2263
ms (found -, connected -, session -, written 214, done 2262)`). What is
slow is the connect: 9396 ms to the remembered peripheral, and in those
nine seconds the scan never saw the lock advertise once. A lock connected
to another central does not advertise, and this lock sits behind the
Wi-Fi bridge, which connects to it for every cloud command; this morning,
with no cloud traffic, the same connect took 611 ms. So every cloud
fallback makes the next Bluetooth connect wait for the bridge, and a
two-minute pause was not enough. The lock dropped the link itself 4 s
after the last command. Amit's taps during the wait cancelled two
commands before the write (each dropped cleanly; the third got the link).

What this says about budgets: the connect wait is the lock coming free,
and for this lock the cloud takes 8–25 s, so a longer Bluetooth wait costs
nothing against it. The right shape is a race, not a budget: start the
cloud after the setup budget but let Bluetooth keep going, first result
wins, the other is cancelled (unlock and lock are idempotent). That is its
own change (TRIAL first); this PR keeps the 6 s budget.

## 2026-11-03 — The race that was not: a longer Bluetooth wait for the screen instead

After the door run, the plan was to race Bluetooth against the cloud:
Bluetooth at once, the cloud after the setup budget, first result wins.
The scoped TRIAL (`scratchpad/trial6`) withdrew it before any code, on
two findings. One was mine: the design kept Bluetooth's setup budget at
6 s and started the cloud at 6 s, so the two never overlapped. The other
is the real one: a cloud command the phone cancels still runs at August
(the PUT is synchronous and relayed server-side; Logbook 2026-10-23), so
after a Bluetooth win the ghost command could land after the opposite
command on the kept link: an open door under a screen that says "Locked".
Today that gap exists only after a cloud fallback; the race would have
made it follow every slow Bluetooth win.

What ships instead: the screen's own taps wait 12 s for Bluetooth (the
person is at the door; the door run's connect completed at 9.4 s, its
setup at 9.8 s) and 6 s for the result (the work after the session has
taken 1.4 s at most); the widget keeps 6 s and 12 s. The 30 s deadline
stays (Amit, 2026-11-01), so the cloud keeps 12 s after both Bluetooth
budgets run out; `CommandDeadline` holds all three numbers and a test
pins the sum. The price: after a 12 s Bluetooth miss the cloud has 18 s,
and two of the seven cloud unlocks measured today (19.9 s and 21.1 s)
would not fit; today's 6 s budget lets them. Also: a cancel that empties
the link's queue during setup now arms a 1 s grace, so a lone cancel does
not leave a pending connect and a kept link; and a setup failure's log
line says whether the scan ever saw the lock advertise, which is the
bridge signal.

Refuted on the way: a "near" signal to pick the budget. The door run saw
no advertisement for 9 s while waiting was right, a miss came 23 s after
an ok, and any history signal re-creates the loop. Open, with a kill
criterion: the widget stays in the loop (a 6 s miss sends a cloud PUT,
the bridge holds the lock for the next tap); if three of ten door visits
show a widget tap falling back after a cloud use within ten minutes, the
widget gets ~10 s of Bluetooth and a cloud leg near 15 s.

## 2026-11-05 — "Sometimes it does nothing": the tap never reached the toggle

Amit: the widget is still flaky, the state machine "bombs", sometimes it
unlocks in seconds and sometimes nothing happens; the app works fine. A
TRIAL before any code (memory,
`deviation_labs/homely_vibes_widget_reliability_trial_2026-11-05.md`), on
the phone's two logs and four Simulator
measurements, found that the state machine never ran for the failures:

1. **No tap reached the widget for a day.** `widget.log` stops at 11-04
   21:54 UTC while `app.log` has six app opens up to 11-05 22:09 and no
   widget tap. Apple: a toggle interaction always reloads the timeline. So
   the failing taps never dispatched an intent.
2. **Every tap that reached the app unlocked**: 14 of 14 over three days,
   10 of 12 over Bluetooth in 2.0–7.8 s since the `bluetooth-central` fix,
   the rest over the cloud in 5.9–23.1 s.
3. **The toggle's hit area was the icon and the caption only.** On the iOS
   27.0 Simulator (the phone's runtime; iOS 26.5 was installed and is not a
   proof), a tap on the caption ran the intent and a tap on the empty corner
   of the same half opened the app. Three quarters of each half opened the
   app, whose open-unlock then ran: "the widget did nothing, the app
   works". Fix: the toggle's body fills its half with `contentShape`; the
   UI test taps near the corner. One rung more was needed: with the halves
   filled, a tap on the sign-in line under the doors ran door 1 instead of
   opening the app (a toggle's hit area reaches past its frame), so that
   line is a `Link` to the body URL, which wins the tap and opens the app
   (measured, same Simulator).
4. **A locked phone makes the toggle inactive** with no reload and no log
   (Apple). This fits Amit's words as well; the logs cannot tell the two
   apart after the fact. From now on the app logs `widget intent` as the
   first line of a tap and `opened by the widget body` (a `widgetURL` on
   the body) when a tap missed, so the next "nothing" is attributable.

Also fixed on the way, from the TRIAL's findings: a tap could run 6 + 12 +
25 = 43 s, past the ~30 s iOS gives a background intent (Apple,
`LongRunningIntent`), and a tap ended that way wrote no result, so its door
stayed "running" for 90 s and every tap on it was ignored. Now a tap has
28 s in all, gate wait included; a cloud request cut off after its send
shows "No reply" (August may still run it), and the running mark expires
at 35 s. The screen's 5-minute exit waits for a widget tap in its process.
Keychain writes update in place instead of delete-then-add, so the widget
never reads an empty state mid-write. The widget's tap goes through a
`DoorUnlocking` parameter, so the Simulator test runs it against
`FakeAugust` end to end. The pre-push code reviewer then caught a leak the
first draft of the tap bound had: with the gate's `enter` alone under the
deadline, a deadline that fires as the gate is handed over discards the
hand-over and leaves the gate held for good, so every later command in that
process waits forever (38 of 300 in its stress run). The gate is taken and
left inside the one task the deadline cancels; `CommandGateTests` pins it.

**Progress on the widget while a tap runs** (Amit's second ask) is not in
this change. WidgetKit defers every reload until the tap's intent returns,
so the only way is to return at once and run the unlock detached; the
TRIAL's blocker is that reloads asked outside an intent lose their budget
exemption and may draw late, and the Simulator cannot measure that. The
measurement is one `BLEWidgetRig` build with a button whose intent returns
at once and a detached task that logs `backgroundTimeRemaining` each second
and asks reloads at 2, 6 and 12 s; three taps on the phone answer it. Rig
data first, then the feature. `LongRunningIntent` (iOS 27) lifts the 30 s
cap but Apple's page says nothing about widgets or where its progress
shows, so it waits too.

## 2026-11-06 — Measured on the phone: a widget cannot show stages during a tap

The TRIAL of 2026-11-05 left one blocker on "progress on the widget while
a tap runs": the only design that could draw mid-tap returns from
`perform()` at once and runs the unlock detached, and nobody had measured
what WidgetKit does with reloads asked after an intent returned, or how
long the process lives. `BLEWidgetRig`'s **Detached** button (README,
"Detached tap measurement") measured both on the phone (iPhone 14 Pro,
iOS 27.0.1, Sideloadly), three clean taps with the app closed and the
phone untouched for 45 s each, plus one tap from the locked Today view.

| Tap (UTC) | `perform()` returned | Reload asked at +2 s | +6 s | +12 s | Bluetooth echo after the return | Process after the return |
|---|---|---|---|---|---|---|
| 00:15:35 | 0.0 s | drawn at +2.1 s | not run | not run | ok, 2.2 s, in the background | logged to +28 s; background task expired at 28.5 s; suspended, resumed at the next tap 8 min later |
| 00:23:34 | 0.0 s | drawn at +2.1 s | not run | not run | ok, 3.1 s | logged to +32 s; expired at 29.6 s; suspended |
| 00:26:24 | 0.0 s | drawn at +2.2 s | not run | not run | ok, 1.7 s | logged to +24 s at the copy; expired later |
| locked Today view | no intent, no reload, no line | | | | | |

An earlier tap (00:12:18), contaminated by a Foreground tap that opened the
app 2 s later, drew all three asked reloads (+2.2, +6.3, +12.6 s): with the
app in the foreground, reloads are exempt from the budget (Apple). In the
background, which is the widget's case, WidgetKit drew the system's own
reload at the return and the first asked reload within 0.1 s, and dropped
the next two; they did not appear later either, over the eight minutes
before the next tap. The Simulator (iOS 27.2) had drawn all three, so it
says nothing about this.

What it decides:

1. **The detached design is dead.** One redraw after the return is all a
   background process gets, so a stage at +2 s could draw but the result
   at the end of the tap (3–28 s) would not, which is worse than today,
   where the result is guaranteed because it is written inside the intent.
   The TRIAL's P1 stands on the phone.
2. **Progress during a tap needs another surface**: a Live Activity on the
   Dynamic Island and Lock Screen, started by the intent
   (`LiveActivityIntent`: Apple says the system launches the app's process
   without opening the app and starts the activity) and updated by the app
   process at each stage. That is a new design with its own TRIAL; nothing
   here starts it.
3. **A background process lives about 30 s after `perform()` returns**
   (the `UIBackgroundTask` budget: `backgroundTimeRemaining` read 32 s at
   the start, the task expired at 28.5–29.6 s), then it is suspended, not
   killed, and resumes at the next tap. Bluetooth delegate callbacks keep
   coming in that window (the echo completed every time). So the 28 s tap
   limit of 2026-11-05 is the right order; the intent's own cap and the
   background task's are the same ~30 s.
4. **A tap on a locked phone does nothing and leaves no trace**, as Apple
   says: no intent, no reload, no log line. With PR #71's logging, a
   "nothing" with no `widget intent` line and no `opened by the widget
   body` line is this case.

## 2026-11-07 — Measured on the phone: a widget tap can drive a Live Activity

The open question of 2026-11-06: a Live Activity started by the widget's
tap would show progress where the widget cannot, but nobody had seen one
started from a widget tap under Sideloadly, or measured whether updates
sent from a background process draw at once (widget reloads did not).
`BLEWidgetRig`'s **Live** button (README, "Live Activity measurement")
measured it on the phone (iPhone 14 Pro, iOS 27.0.1, Sideloadly, app
closed). Its intent has this app's tap modes plus `LiveActivityIntent`;
inside `perform()` it starts an activity, runs the Bluetooth echo beside
it, updates once a second for 20 s and ends it. Each presentation draws
the last second sent beside a system timer that ticks with no update.

| Tap (UTC) | `Activity.request` | Updates | Echo beside it | End | Widget redraw |
|---|---|---|---|---|---|
| 01:41:44, :48, :50 (three, overlapping) | ok, 34 / 21 / 16 ms | 20 each, `update()` 1–6 ms | ok, 1.6–1.7 s | +20.1 s each | once, 0.3 s after the last ended |
| 01:45:52 | ok, 18 ms | 20 | ok, 1.6 s | +20.1 s | 0.3 s after the end |
| 01:55:36 | ok, 28 ms | 20 | ok, 2.7 s | +20.1 s | 0.3 s after the end |

What it decides:

1. **A widget tap starts an activity with the app in the background.**
   `LiveActivityIntent` plus `NSSupportsLiveActivities` is all it takes;
   Sideloadly's signing needs nothing more. The app never came forward.
2. **Background updates draw live.** Amit watched the sent count keep pace
   with the system timer to +20: the expanded Island for about 2 s at the
   start, then the compact one for the whole run. This is the opposite of
   widget reloads (2026-11-06), so progress during an unlock is possible.
3. **The activity costs the unlock nothing.** The echo took the same time
   as without it (1.6–2.1 s before), and every ActivityKit call returned
   in under 35 ms.
4. **Overlapping taps confuse the Island.** With three activities running,
   all three ran to the end, but the Island showed one and emptied at
   about 17 s on its clock, near the moment another activity ended. With
   one tap at a time the Island ran to +20. Two doors tapped together is
   this case, so the app needs one activity for both doors or a rule for
   which one the Island shows.
5. **The widget still redraws only after the last tap returns**, as on
   2026-11-03; the activity does not change that.

Not measured: whether the Lock Screen keeps an ended activity for the
12 s asked (`dismissalPolicy: .after`), and a Live tap from the locked
Today view (expected to do nothing, as for every widget button). Found on
the Simulator: a UI test that calls `launch()` or `activate()` on the app
while the intent runs starts a new process and kills the intent's.

## 2026-11-07 — The widget tap's Live Activity, built from the rig

Built on the Live measurement above, after a scoped TRIAL (memory,
`deviation_labs/homely_vibes_live_activity_trial_2026-11-07.md`). What the
TRIAL changed from the first sketch:

- **The stages come from two lines, not from the Bluetooth link.** The
  link's timing line has no hook, and needs none: the owner's stages are
  only the path. `operateHoldingGate` reports `bluetooth` before
  `AugustBLELink.run` and `cloud` before the request goes out, both after
  the command gate and the key check, so a door waiting for the other
  door's command, or a lock with no key, never claims Bluetooth.
- **One stream, one task.** The client reports from inside the deadline's
  task, off the main actor. A task per update could land out of order; the
  stages go through an `AsyncStream` to one task, and the end waits for it,
  so no update lands after the end.
- **Start after the repeat-tap check.** A repeat tap on a running door
  returns early; an activity started before that check would never end.
- **One activity at a time.** Overlap empties the Island early (the rig), so
  a tap that starts while another runs in the process gets none. Each start
  first ends any older activity (one in its Lock Screen hold, or one a dead
  process left), and a stale one reads "Check the door".
- **No hold on the Island.** It drops an ended activity; the Lock Screen and
  the widget keep the result (Amit's call).
- **Nothing waits before the unlock, and the widget's result comes first.**
  The pre-push review found that ending old activities was awaited before
  the unlock, and the activity's end before the widget's result write, so a
  slow ActivityKit call could cost the unlock time or, at the ~30 s limit,
  the widget's result. Old activities now end on their own tasks, the
  request is synchronous, and the result is written before the end.

On the Simulator (iOS 27.2) the compact Island showed the lock icon and the
timer from the tap about 3 s after it, and left at the end; the system log
had the activity dismissed 12 s after its end. `XCUIScreen` screenshots taken
inside the UI test never showed the Island, while `xcrun simctl io
screenshot` frames taken at the same time did, so the UI test checks the
tap, not the Island. On the phone (02:40 UTC, both doors over Bluetooth in
2.6 and 6.0 s from the widget, with the new `name` parameter) Amit: "island
looks good".

## 2026-11-07 — Robustness TRIAL with formal verification: what changed

Asked for after the front door failed to lock from the app (memory,
`deviation_labs/homely_vibes_august_robustness_trial_2026-11-07.md`). The
front door is direct, not bridged (the garage is), and rarely answers over
Bluetooth: 2 connects (3.7 and 4.0 s) and 2 misses in three days, against
28 garage connects of 0.2–1.5 s. Both lock attempts spent 12 s on a scan
that never saw it, then the cloud: the first request was cancelled by a
re-tap after 1.6 s, the second cut by the 30 s deadline after 19.4 s while
the screen said "Timed out". Two new Quint models and the session's own
reading of `app.log` found what to change:

- **A tap after a failed lock unlocked.** A failure set the door unknown,
  and a tap on an unknown door unlocks. The phone did it twice on 11-03
  (a jam on lock, then the next tap unlocked). Now a tap after a failure
  repeats the failed command (`retry`; `noUnlockAfterFailedLock` in the
  model, `withDeadline` violates, `withRetry` holds).
- **The screen could show a state the lock was not in, unwarned.** A cloud
  request the phone drops still runs at August and can land after the next
  command (`ghost_order.qnt`, a 6-step trace). Now dropping one shows "An
  earlier request may still move the door" for 60 s, and the expiry of the
  background time makes the door unknown (`ghostWarned` holds
  `honestOrWarned` whether August keeps order or not). Routing the next
  command to the cloud was rejected: it holds only if August runs requests
  in order.
- **"Timed out" when the request was with August.** The screen now says
  "Sent to August, no reply yet", lets the request run to 60 s (Amit) and
  shows a late reply as a line, never as a success.
- **One gate per lock** (Amit): a tap on one door no longer waits for the
  other door's command; `gate.qnt` checks the gate itself.
- Smaller: the cloud fallback's state read used the selected lock, not the
  commanded one, so a widget tap on the other door could report the wrong
  door; a read that disagrees with the command is now unknown. A cancel
  that landed before the Bluetooth command registered was lost (a Swift
  probe showed it). A tap older than 35 s could clear a newer tap's widget
  mark. Old Live Activities get up to 0.5 s to end before a new one starts,
  and none wait in the usual case. An August reply without the offline key
  no longer deletes the stored one. The three-item key migration is gone.
- **Logging.** Cancel and jam lines name the lock; a `cloud … sent` line
  marks the point after which August holds the request; after a request
  the phone gave up on, or a jam, August's door state is read at +10 s and
  +30 s and logged, so the next "it did not lock" has an answer.

Refuted: remembering a Bluetooth miss per lock and cutting the next setup to
2 s (it would have cut both front-door connects that worked, and for the
garage it speeds up the bridge loop of 2026-11-03), and skipping Bluetooth
while the bridge is busy. Open, measured: the garage's six "jammed" (0x1F,
yalexs `MECH_POSITION`) reports. Four had no earlier movement from us and two
followed an unlock by 1–3 s; the door-state reads after a jam will say more.

## 2026-11-08 — Lock Both on the widget; two doors on the screen, and only a tap sends

Amit asked for three widget buttons, with the center locking both doors, and an
app with both doors one below the other, text to the right of the buttons,
nothing unlocked on open, and the first tap on either door unlocking.

- **The widget's "nothing locks" rule made a door's commands one-way, so a
  cut-off unlock was harmless. With Lock Both it is not.** An unlock that ended
  "No reply" stays with August (the ghost of 2026-11-03), and it can land after a
  later lock: an open door under "Locked". `DoorState.unanswered` keeps each
  door's unconfirmed unlock for 60 s (the screen's window), and Lock Both reads
  "No reply" over it. A failed one counts too: a cloud request that ended in a
  network error may still have gone out. A held lock moves the door the same way,
  so it stops nothing. Not covered: an unlock the app's screen dropped.
- **One door can reopen during Lock Both.** A fast door locks, an unlock tap on it
  succeeds, the slow door locks: an open door under "Locked" (pre-flight review).
  An unlock tap started since Lock Both's tap keeps the center from "Locked".
- **A sign-out can race the launch's list fetch.** A late reply would write the
  list back, and a session with a list skips the code form; a re-login after a
  401 could write the token back. Both now check they are still signed in.
- **A reply is not a lock.** The cloud reply carries the lock's state, which may
  be unknown or even unlocked, so "Locked" needs `state == .locked`
  (`LockState.lockOutcome`). An unlock tap has always counted any reply.
- **Lock results are written together when the tap ends.** A door's result is
  held 12 s and WidgetKit redraws only after the intent ends, so a fast door's
  failure written as it happened would be gone before a slow door let the
  widget draw.
- **The first tap after a return unlocks.** The door may have moved while the
  app was away, so an idle door becomes unknown. The exception is a retry: a
  failed lock stays a lock across a return, or the retry rule of 2026-11-07
  breaks.
- **`timedOutWhileAway` is gone.** It stopped a return from unlocking after a
  timeout; a return never unlocks now. `onlyATapSends` in the model pins that.
- **The door list is cached in the Keychain.** A door must work with no network;
  the fresh list loads behind it. A build with a session and no list (this
  update) fetches the list instead of asking for a new sign-in.
- The new intent is `SecureDoorsIntent`: a name with no word from the module
  names (2026-11-01).
- **The screen's title is a config key.** The owner's title is on the security
  scan's denylist, so `config/local.yaml` holds it and `build_ipa.sh` builds it in.
- **A whole card is one button.** VoiceOver and the UI tests read a door's status
  from the button's value.
- **No `.glassEffect` in the widget.** Apple documents none inside widget content,
  and the system renders the container as glass in clear mode. The widget repeats
  the screen's tinted circle instead, and the toggle rules of 2026-11-02 and
  2026-11-05 stand.

## 2026-11-09 — The widget waits 12 s for Bluetooth; both paths at once was tried and taken out

Amit: the widget's garage unlock failed once, and the app works. The phone's
`app.log` had the tap (Nov 8, 17:09 PST): the Bluetooth connect missed its 6 s
(`setup timed out while connecting; scan saw the lock: no`), the cloud command
then took 18.8 s, and the door opened at 25.3 s. Since Nov 6, four of eleven
widget connects missed the 6 s and seven took 0.4–4.6 s (the garage's five,
0.4–2.2 s). The screen gives Bluetooth 12 s, which is why the app looks better.

**What shipped.** A widget tap uses the screen's Bluetooth budgets (12 s to a
session, 6 s from there), and the cloud only as the fallback, for unlock and
for lock (Amit, 2026-11-09). This replaces the widget's 6 s and 12 s of
2026-11-03. A setup miss leaves the cloud 16 s of the tap's 28 s, where it
had 22 s: a cloud command as slow as that 18.8 s one now ends "No reply",
though the door may still move. The 28 s cannot grow: iOS ends a background
intent at about 30 s.

**What was tried first and taken out the same evening.** Amit chose to send
Bluetooth and the cloud together from the tap, the first to move the door
answering; a scoped TRIAL shaped it (memory,
`deviation_labs/homely_vibes_parallel_paths_trial_2026-11-09.md`) and it went
onto the phone. One session of four taps showed two things:

- **A cloud lock from this app makes the front lock beep 12 times.** With
  both paths, every Lock Both sends one. Amit's words: "one door still beeped
  12 times"; the front door, beeps from its speaker, on the lock only, never
  on the unlock; a remote lock from the official August app "makes a single
  beep, not 12"; the app's screen, which locks over Bluetooth, is quiet. The
  old build did it too, on the one Lock Both that fell back to the cloud
  (Nov 9, 18:19 PST). The app sent one request each time, and August's feed
  shows one `remote_lock`; the lock path has no loop.
- **The two paths fight for the lock's one Bluetooth link.** The garage's
  connect took 9.0 s (0.4–2.2 s before). The cloud opened the door first, the
  Bluetooth command then answered "ok" in 158 ms without moving anything, and
  the log said "via Bluetooth". The risk was named before the build
  (Logbook 2026-11-03: the bridge holds the lock for a cloud command) and
  Amit chose to learn it from use.

**Why 12 beeps is still open.** A second TRIAL (memory,
`deviation_labs/homely_vibes_twelve_beeps_trial_2026-11-09.md`) refuted "the
lock's normal sound for a cloud lock" (that is one beep) and ruled out a
duplicate command, a lock sent to a locked door, the garage, the motor and
background Bluetooth. Two differences from the official app's quiet remote
lock are left: this app's request (`PUT /remoteoperate/{lock}/lock`, the
synchronous form, as yalexs' sync call; the official app's is not known), and
the cloud unlock that came 3–9 s before the lock both times. Not tested. A
widget lock that falls back to the cloud will still beep 12 times.

**Kept from the both-paths work:**

- **An unlock tap with no end counts as an unlock that may still land.** A
  process that dies during a tap writes no result, and its cloud unlock may
  be out; Lock Both read "Locked" over it. `DoorState.running` for that door
  now stops "Locked" for 60 s from the tap's start, and the next tap moves it
  to `unanswered` (found by the pre-push review of the both-paths build).
- **The log says what the lock said.** Nothing recorded what a lock did, so
  "12 of what?" had no answer for an evening. Now: every frame the lock sends
  that is not about the waiting command (`lock pushed <hex>`; byte 4 `02` is
  the lock's state, byte 8 its value: `03` unlocked, `04` locking, `05`
  locked), an answer to a command that is not waiting on this link,
  August's reply to a cloud command (its status, its numbers, the names of
  its other fields), and `no motion` on a Bluetooth answer that came in under
  half a second (the lock was probably in that state already: 97–178 ms in
  the phone's log for such answers, against 1.0–2.1 s for a real motion). The file keeps 600
  lines. The frames are seen only while a link is up, and a widget tap's
  link closes at its result.

**A command for the state the lock is already in does not move the motor**
(garage, one sample: the 158 ms answer above, no `locking`/`unlocking` frame).
No front-door sample.

**August's activity feed is the second witness** for "what did the lock do":
`GET /houses/{id}/activities` with the cached token of `August/` lists every
remote command with its time and source. Bluetooth commands from this app do
not appear there; the official app's do.

**On process.** I wrote Amit's "Heard the lock" into a commit message as "the
motor ran about 12 times". He had not said motor; it was the speaker. A
report goes into the record in the reporter's words.
