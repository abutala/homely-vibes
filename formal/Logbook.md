# formal — Logbook

Learnings and landmines. How to use this module: [README.md](README.md).

---

## Incidents

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

`quint run` samples. It is the quick check because it needs no JDK, and
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
