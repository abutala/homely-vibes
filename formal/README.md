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
make formal 2>&1 | tee /tmp/formal.log             # randomized search over every pinned outcome
make formal-verify 2>&1 | tee /tmp/formal_verify.log  # exhaustive proof of the same outcomes
```

`formal-verify` needs JDK 21 (macOS: `brew install openjdk@21`, which is keg-only and
leaves your default `java` alone; the script finds it, or honours `JAVA_HOME`).

None of these is part of `make setup`, `make lint` or `make test`, so the prod host never
installs Quint. CI runs both ([formal.yml](../.github/workflows/formal.yml)) when `formal/`,
`lib/file_lock.py`, `RingBeams/` or the Makefile change; it is not a required check.

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
| `make formal` ([check.sh](check.sh)) | `quint run`, randomized | a real counterexample | only "not found": never a proof |
| `make formal-verify` ([verify.sh](verify.sh)) | `quint verify`, Apalache | a counterexample the solver built | a proof over every execution of the model |

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

Trace validation (replay real logs against the model) is the next step up.

## Adding a model

One `.qnt` per design, written as a parametric module with a `const` per code switch
under test, plus one instance module per variant. Add a row per (instance, property) to
`check.sh`. Do not copy household identifiers into a model.
