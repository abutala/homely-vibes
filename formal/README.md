# formal

Formal models of the concurrency and protocol designs that tests exercise badly:
state machines where the bug lives in an interleaving nobody wrote a test for.
Models are [Quint](https://quint-lang.org) (TLA+ semantics, TypeScript-like syntax).
They describe states and transitions, not code, so they stay valid whatever language
the implementation is in. Gotchas and findings: [Logbook.md](Logbook.md).

| Model | Question it answers |
|---|---|
| [ring_token_lock.qnt](ring_token_lock.qnt) | Is the flock around the shared Ring refresh token airtight? Instances: `current` (before the sidecar inherited the lock), `orphanFixed` (the code now), `allFixed` (`auth` also locked: not built). |

## Setup and run

```bash
make formal-deps 2>&1 | tee /tmp/formal_deps.log   # pinned Quint; needs npm
make formal 2>&1 | tee /tmp/formal.log             # check every pinned outcome
```

Neither is part of `make setup`, `make lint` or `make test`, so the prod host never
installs Quint. `make formal` is not wired into CI yet.

Explore one property by hand (add `--mbt` for the action sequence):

```bash
cd formal && npx quint run ring_token_lock.qnt --main=current \
  --invariant=lockedWritersExclusive 2>&1 | tee /tmp/quint_current.log
```

## What a result means

`quint run` is a randomized search. **A violation is a real counterexample; "holds" is
only "not found", never a proof.** [check.sh](check.sh) pins the expected outcome of every
(instance, property) pair, so both a regression and a model that stops reproducing its
bug fail. For an exhaustive proof use `quint verify` (Apalache), which needs JDK 17 or
newer; see the Logbook for the error JDK 11 gives.

## Linking a model to code

A model proves nothing about the code until something ties them together. Today that is
a test per modelled hazard, named for the model property it mirrors:

| Model property | Test |
|---|---|
| `lockedWritersExclusive`, sidecar orphan | `lib/test_file_lock.py` and `RingBeams/test_beams_manager.py`, the `*_after_parent_is_killed` tests |

Trace validation (replay real logs against the model) is the next step up.

## Adding a model

One `.qnt` per design, written as a parametric module with a `const` per code switch
under test, plus one instance module per variant. Add a row per (instance, property) to
`check.sh`. Do not copy household identifiers into a model.
