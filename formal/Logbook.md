# formal — Logbook

Learnings and landmines. How to use this module: [README.md](README.md).

---

## Incidents

### 2026-11-06 — The ScreenShare launch model, proved with TLC

[screenshare_connect.qnt](screenshare_connect.qnt) models one launch of a tunnel app against a
link that drops, an ssh that goes stale, a remote VNC that stalls or is off, a password prompt
and a user's Cancel. What it taught:

- **Apalache could not finish it; TLC proves it in about a second.** One Apalache row at 40
  steps ran 15 minutes with no result. The model is finite (enums, small counters), so
  `quint verify --backend=tlc` walks the whole state graph: `shareFinal` has 64,063 distinct
  states, depth 39, queue empty. A model opts in with a `// backend: tlc` line; `verify.sh`
  reads it.
- **Random search missed real counterexamples.** At 20,000 samples one row came back
  `violated` in one run and `holds` in the next, and `make formal` at 200,000 samples missed
  `shareProposed noFailedHealthyLaunch` (the first design, `shareProposed`, then needed a slow connect on all three attempts). TLC
  settled both, so [check.sh](check.sh) uses TLC for a `// backend: tlc` model as well.
- **A model that is too kind proves the wrong design.** The first version made cleanup one
  atomic step and let an old session's window turn into its dialog at once; both hid real
  races (a session that comes up during cleanup; a dead window with the live session's
  title). The TRIAL's refutation split the steps and the model then found them, plus one
  more: a stalled connect that turns into a password prompt during cleanup.
- **Instance names are global across `formal/`.** `model_of` takes the first file that
  declares the module, and `ring_token_lock.qnt` already has `current`; the instances here are
  `shareMain`, `shareProposed`, `shareFinal`.
- **Removing one fix at a time shows each is needed.** Each `shareFinal` switch was turned off
  alone and TLC re-run; the verdict lists which property each one keeps.

### 2026-11-01 — The AugustUnlock command model reproduces the stuck screen

[august_unlock_command.qnt](august_unlock_command.qnt) models one lock command with a
phone nap. Two things it taught in the first hour:

- **Random search cannot reach a 30-tick stall.** With the app's real 30 s limit, a
  stall needs the simulator to pick `tick` 31 times in a row while the phone naps; it
  never did, and the "before" instance came back `holds` for lack of reach. Time units
  are abstract: the limit is 3 ticks in the model, which keeps every rule and makes the
  stall reachable. A `// max-steps:` line per model tells the scripts the bound.
- **A model lets the phone nap in the foreground; iOS does not.** The first version found a
  "stuck" command on main: nap in the foreground, wake, and nothing fired the deadline
  until the next tick. On a phone, screen-off backgrounds the scene, so a nap always ends
  in the resume path, which checks the wall clock. The model now backgrounds on `sleep`,
  and `wakeFiresDeadline` (assumption A2) is a switch: `resumeOnly` drops it and the
  resume check alone keeps `noStuckCommand`.

`noSurpriseMoves` is pinned `violated` in every instance: a cloud command the phone gave
up on still runs at the lock (the four beeps of 2026-11-01). That is a property of
August, not a bug in the model or the app; the pin keeps it visible.

### 2026-10-04 — The exhaustive run agrees with the simulator

Apalache confirmed every row of [outcomes.txt](outcomes.txt). On the shipped code
(`orphanFixed`) the lock-using writers are proved mutually exclusive; the sidecar-orphan
counterexample exists only in `current`; and the `auth` counterexamples remain in
`orphanFixed`, closing only in `allFixed`. The proof is of the model under assumption A1,
not of the code.

### 2026-10-04 — The model found a hole the lock tests could not

`lib/test_file_lock.py` showed the flock works; nothing checked that *callers* keep the
critical section airtight. Modelling the callers showed that a SIGKILLed RingBeams
parent leaves its Node sidecar alive and refreshing outside the lock, because flock is
released when the holder dies and the sidecar never held it. Reproduced with a real
process kill before any fix. Fix and details: [RingBeams/Logbook.md](../RingBeams/Logbook.md).

---

### 2026-11-07: the AugustUnlock screen could show a door state the lock was not in

A TRIAL modelled what the shipped model leaves out: the real door, each held
command's direction and August's order (`ghost_order.qnt`). Quint found, in 6
steps, a cloud unlock replaced by a tap to lock that succeeds over Bluetooth,
then August running the held unlock: the lock is open, the screen says
"Locked". The shipped model could not see it: its `door` is the shown one and
`heldAtAugust` is a bare count. Fixed by a warning, not by ordering (see the
AugustUnlock Logbook, 2026-11-07). The same TRIAL added `noUnlockAfterFailedLock`
to `august_unlock_command.qnt` after the phone showed a tap after a failed lock
unlocking.

## Landmines

### Open: `ring_manager.py auth` runs without the lock

`orphanFixed` still violates `mutualExclusion` and `noInvalidGrant`: the interactive
login writes the token file with no lock, so it can overlap a cron run. Not fixed:
holding the lock across an interactive 2FA prompt would time out the cron jobs
(60 s) and page P1 during every login. `allFixed` shows what locking it would give.
Rests on **assumption A1**: a fresh login invalidates the refresh token Ring issued
before it. Unconfirmed; if false this row is benign and only the sidecar finding stands.

### An instance of a parametric module is `import m(c = v).*`, nothing else

`import m(c = v) as x` followed by `export x.*` typechecks and then fails at run time
with `QNT500 Uninitialized const`. `import m(c = v).*` with no `from` works when the
instances live in the same file as the module.

### `quint verify` needs JDK 21: JDK 11 and 17 both fail, differently

```
Unrecognized VM option 'G1PeriodicGCInterval=600000'                      (JDK 11)
UnsupportedClassVersionError: ... class file version 65.0, ... up to 61.0  (JDK 17)
```

Apalache's own docs recommend JDK 17, but the distribution Quint downloads is compiled for
Java 21 (class file version 65), so 17 fails at class loading. On macOS use
`brew install openjdk@21` (keg-only; the default `java` is untouched) and let
[verify.sh](verify.sh) find it. The first `verify` downloads Apalache into `~/.quint`
before failing, so the failure is not a network problem.

### Quint's TLC backend never checks deadlocks

`quint verify --backend=tlc` starts TLC with `-deadlock`, which turns the deadlock check off,
and `--tlc-config` cannot turn it back on. To check one, compile and run TLC yourself:

```bash
npx quint compile --target=tlaplus --main=shareFinal screenshare_connect.qnt > /tmp/m.tla
sed -i '' '/^# /d' /tmp/m.tla; printf 'INIT q_init\nNEXT q_step\n' > /tmp/m.cfg
java -cp ~/.quint/apalache-dist-*/apalache/lib/apalache.jar tlc2.TLC -workers auto /tmp/m.tla 2>&1 | tee /tmp/tlc_deadlock.log
```

`shareFinal` passes; the same run with `idle` removed reports `Deadlock reached`, so the check
works. `quint compile` needs JDK 21 on `PATH`, not only in `JAVA_HOME`.

### `quint verify` calls a finished model a deadlock

A model whose actors all terminate has no enabled action at the end, and Apalache reports
`reached a deadlock` as a violation once the step bound outlasts the run. The model has an
explicit `terminal` state with an `idle` step, so a state stuck *before* every actor
finishes is still reported as a deadlock while a normal finish is not.

### `quint run` exits 1 for a counterexample and for a broken model alike

A missing instance (`QNT405`), an uninitialized const (`QNT500`) and a real
`Invariant violated` all exit 1. A harness that reads the exit code alone passes every
"violated" row against a model that no longer loads. [check.sh](check.sh) reads what Quint
prints and treats anything unrecognized as `error`, which matches no expectation.

### "No violation found" from `quint run` is not "verified"

`quint run` samples. It is the quick check because it needs no JDK (except for a
`// backend: tlc` model, which both scripts check with TLC), and
[check.sh](check.sh) pins both polarities to keep it honest. Say "not found in random
traces", never "proved", of a `check.sh` result. Only [verify.sh](verify.sh) proves.

### Scope the model leaves out, deliberately

A crash between "Ring rotated the token" and "file written" loses the token whatever the
locking does; a hung sidecar is bounded by `RingBeams/watchdog.js`, which is liveness and
not modelled. A model that tried to cover them would bury the property it exists for.

---

## References

- Quint language and tooling: https://quint-lang.org
- Apalache (the exhaustive checker behind `quint verify`): https://apalache-mc.org
- Apalache install docs (recommend JDK 17; the build Quint 0.33 downloads needs 21): https://apalache-mc.org/docs/apalache/installation/jvm.html
