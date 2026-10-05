# formal — Logbook

Learnings and landmines. How to use this module: [README.md](README.md).

---

## Incidents

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

### `quint verify` on JDK 11 fails with `Unrecognized VM option`

```
Unrecognized VM option 'G1PeriodicGCInterval=600000'
Error: Could not create the Java Virtual Machine.
```

Apalache's launcher passes a JVM flag newer than JDK 11. Use JDK 17 or newer, e.g.
`JAVA_HOME=$(/usr/libexec/java_home -v 17) npx quint verify ...`. The first `verify`
downloads the Apalache distribution (outside the repo, into Quint's cache) before
failing, so the failure is not a network problem.

### `quint run` exits 1 for a counterexample and for a broken model alike

A missing instance (`QNT405`), an uninitialized const (`QNT500`) and a real
`Invariant violated` all exit 1. A harness that reads the exit code alone passes every
"violated" row against a model that no longer loads. [check.sh](check.sh) reads what Quint
prints and treats anything unrecognized as `error`, which matches no expectation.

### "No violation found" is not "verified"

`quint run` samples. It needs no JDK, so it runs anywhere, and
[check.sh](check.sh) pins both polarities to keep it honest. Say "not found in N random
traces", never "proved", for a `make formal` result. `make formal-verify` is the
exhaustive one and runs in CI, where JDK 17 is installed.

### `quint verify` reports a deadlock for a model whose actors simply finish

```
[violation] Found an issue
error: reached a deadlock
```

Apalache checks for deadlocks by default, and a model where every actor runs once ends
with no action enabled. That is termination, not a bug, but it failed every "holds" row.
[apalache.json](apalache.json) sets `checker.no-deadlock` (singular; the plural is
rejected as an unknown key) and `check.sh verify` passes it. A model that must never get
stuck needs its own liveness property instead of this default.

### Two `quint verify` runs at once collide

Apalache listens on one fixed port, so a second `make formal-verify` on the same host
fails with `Address already in use` or a dropped connection. `check.sh` reads that as
`error`, which fails the row; rerun once the other has finished.

### A green model says nothing about a code change

The switches (`childInheritsLock`, `authTakesLock`) are set by hand. Delete `pass_fds`
from `run_sidecar` and every row still passes: only
`test_orphaned_sidecar_keeps_token_lock_after_parent_is_killed` in
`RingBeams/test_beams_manager.py` notices. So the workflow runs on changes to the model, not to the code it
describes; a green `formal` check on a RingBeams change would have read nothing of it.

### The inherited lock is bounded by the sidecar timeout, not by the model

A hung orphaned sidecar holds the lock at most until its watchdog fires at
`ring_beams.sidecar_timeout_seconds`, and `acquire_lock` waits 60 s by default. The
shipped default keeps the first below the second, so a waiting RingSecurity outlasts
the orphan. Raise the sidecar timeout past the acquire timeout and a hung orphan can
become a `LockTimeoutError` page instead. Nothing checks this ordering.

### Scope the model leaves out, deliberately

A crash between "Ring rotated the token" and "file written" loses the token whatever the
locking does; a hung sidecar is bounded by `RingBeams/watchdog.js`, which is liveness and
not modelled. A model that tried to cover them would bury the property it exists for.

---

## References

- Quint language and tooling: https://quint-lang.org
- Apalache (the exhaustive checker behind `quint verify`): https://apalache-mc.org
- Apalache JVM requirement (JDK 17+): https://apalache-mc.org/docs/apalache/installation/jvm.html
