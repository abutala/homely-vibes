# formal

Formal models of the concurrency and protocol designs that tests exercise badly:
state machines where the bug lives in an interleaving nobody wrote a test for.
Models are [Quint](https://quint-lang.org) (TLA+ semantics, TypeScript-like syntax).
They describe states and transitions, not code, so they stay valid whatever language
the implementation is in. Gotchas and findings: [Logbook.md](Logbook.md).

| Model | Question it answers |
|---|---|
| [ring_token_lock.qnt](ring_token_lock.qnt) | Is the flock around the shared Ring refresh token airtight? Instances: `current` (before the sidecar inherited the lock), `orphanFixed` (the code now), `allFixed` (`auth` also locked: not built). |
| [august_unlock_command.qnt](august_unlock_command.qnt) | Can an AugustUnlock command hold the screen after the phone naps, can a return to the app unlock by itself after a timeout, is Change Lock ever refused, and what does a cloud command the phone gave up on do? Does a tap after a failed lock unlock? Does anything but a tap send? In `tapToUnlock` the Change Lock action is Sign Out. Instances: `beforeDeadline` (before #57), `deadlineOnly` (#57's first push), `withDeadline` (#57, before the retry rule), `withRetry` (#77), `resumeOnly` (`withRetry` if a passed deadline does not fire on wake), `tapToUnlock` (the app now: two doors on screen, only a tap sends). |
| [ghost_order.qnt](ghost_order.qnt) | Can the AugustUnlock screen show a door state the lock is not in, when August still holds a command the phone dropped? Instances: `ghostBefore` (before #77: yes, unwarned), `ghostWarned` (now: only with the "may still move the door" line), each also with August running commands out of order. |
| [gate.qnt](gate.qnt) | Is AugustUnlock's per-lock command gate ever held without a holder, or left with a cancelled waiter? Instances: `gateShipped`, `gateNoPostCheck` (the post-queue cancel check removed). |
| [screenshare_connect.qnt](screenshare_connect.qnt) | Does a ScreenShare tunnel app's launch leave a hung window or a dead tunnel behind, fail on a healthy link, end a working session or a password prompt, take a frozen session for a live one, or reopen what the user cancelled? Instances: `shareMain` (before 2026-11-06), `shareProposed` (first retry design), `shareFinal` (the launcher now). Proved with TLC (`// backend: tlc`). |

## Setup and run

```bash
make formal-deps 2>&1 | tee /tmp/formal_deps.log   # pinned Quint; needs npm
make formal 2>&1 | tee /tmp/formal.log             # randomized search over every pinned outcome
make formal-verify 2>&1 | tee /tmp/formal_verify.log  # exhaustive proof of the same outcomes
```

`formal-verify` needs JDK 21 (macOS: `brew install openjdk@21`, which is keg-only and
leaves your default `java` alone; the scripts find it, or honour `JAVA_HOME`). So does
`formal` for a model marked `// backend: tlc`: both scripts check it with TLC, which runs
from the Apalache jar that `formal-verify` downloads, so run `formal-verify` once first.

None of these is part of `make setup`, `make lint` or `make test`, so the prod host never
installs Quint. CI runs both ([formal.yml](../.github/workflows/formal.yml)) only on demand,
with a 60-minute limit: `gh workflow run formal.yml --repo abutala/homely-vibes --ref <branch>`.
Run `make formal` locally before pushing a model change. It is not a required check.

Explore one property by hand (add `--mbt` for the action sequence):

```bash
cd formal && npx quint run ring_token_lock.qnt --main=current \
  --invariant=lockedWritersExclusive 2>&1 | tee /tmp/quint_current.log
```

## What a result means

The expected outcome of every (instance, property) pair lives in [outcomes.txt](outcomes.txt),
so both a regression and a model that stops reproducing its bug fail.

| Check | Engine | "violated" means | "holds" means |
|---|---|---|---|
| `make formal` ([check.sh](check.sh)) | `quint run`, randomized (TLC for a `// backend: tlc` model) | a real counterexample | only "not found": never a proof (TLC: a proof) |
| `make formal-verify` ([verify.sh](verify.sh)) | `quint verify`, Apalache (TLC for a model with `// backend: tlc`) | a counterexample the checker built | a proof over every execution of the model |

A model with a `// verify: search-only` line (today `ghost_order.qnt` and `gate.qnt`) is
skipped by `verify.sh`: only the randomized search covers it until its state space is
sized for a CI run.

A proof is about the **model**: it holds only under the model's assumptions (A1 in
[ring_token_lock.qnt](ring_token_lock.qnt)) and says nothing about whether the code matches
it. `verify.sh` documents why its step bound covers every run; raise it when you add an
action or an actor.

## Linking a model to code

A model proves nothing about the code until something ties them together. Today that is
a test per modelled hazard, named for the model property it mirrors:

| Model property | Test |
|---|---|
| `lockedWritersExclusive`, sidecar orphan | `lib/test_file_lock.py` and `RingBeams/test_beams_manager.py`, the `*_after_parent_is_killed` tests |
| `noStuckCommand`, `noAutoUnlockAfterAwayTimeout`, `changeLockAlwaysPossible`, `noUnlockAfterFailedLock`, `onlyATapSends` | `AugustUnlock/Tests/AugustBLEProtocolTests/CommandMachineTests.swift` (the pure `CommandMachine` each door's `DoorController` drives; a stress run with simulated Bluetooth and cloud, late replies included) |
| `honestOrWarned` (ghost_order) | `CommandMachineTests`: `testDroppingACloudCommandWarnsForAMinute`, `testChangeLockLeavesTheOldLocksWarningBehindButExpiryWarns`, `testATimeoutAfterTheCloudLetsTheRequestRunAndShowsItsLateReply` |
| `cancelledWaiterDrops` (gate) | `AugustUnlock/Tests/AugustBLEProtocolTests/CommandGateTests.swift` |
| `cleanFailure`, `noLiveSessionKilled`, `promptNeverKilled` and the rest of `screenshare_connect` | `ScreenShare/test_build_app.py` (the probe and stop shell against real local sockets) and `ScreenShare/test_launcher_decide.py` (the launcher's pure `decide` and `classify` handlers under `osascript`) |

The glue in `DoorController` (the deadline task, the background keep-alive, the stage stream) is
covered only by the Simulator UI tests, not by a model.

Trace validation (replay real logs against the model) is the next step up.

## Adding a model

One `.qnt` per design, written as a parametric module with a `const` per code switch
under test, plus one instance module per variant. Add a row per (instance, property) to
`outcomes.txt`. Do not copy household identifiers into a model.
