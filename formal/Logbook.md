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

`quint run` samples. It is the committed check because it needs no JDK, and
[check.sh](check.sh) pins both polarities to keep it honest. Say "not found in N random
traces", never "proved", until `quint verify` has run.

### Scope the model leaves out, deliberately

A crash between "Ring rotated the token" and "file written" loses the token whatever the
locking does; a hung sidecar is bounded by `RingBeams/watchdog.js`, which is liveness and
not modelled. A model that tried to cover them would bury the property it exists for.

---

## References

- Quint language and tooling: https://quint-lang.org
- Apalache (the exhaustive checker behind `quint verify`): https://apalache-mc.org
- Apalache JVM requirement (JDK 17+): https://apalache-mc.org/docs/apalache/installation/jvm.html
