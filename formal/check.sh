#!/bin/sh
# Pins what Quint must (not) find in ring_token_lock.qnt.
# A flipped result in either direction fails: a "holds" row that now violates is
# a regression; a "violated" row that now holds means the model stopped
# reproducing the bug it documents.
#
#   check.sh          randomized simulator, every row. Search, not proof.
#   check.sh verify   Apalache, the "holds" rows only, every trace up to
#                     MAX_STEPS. Needs JDK 17 or newer. See README.md.
set -eu
cd "$(dirname "$0")"

MODE="${1:-run}"
SAMPLES="${QUINT_SAMPLES:-200000}"
# Each actor runs once and no action repeats, so no trace is longer than the
# number of actions in `step`. A bound above that makes `verify` complete.
# Every trace therefore ends with nothing enabled, which Apalache reports as a
# deadlock unless apalache.json turns that check off.
MAX_STEPS=20
failed=0

# Quint exits 1 for a counterexample and for a broken model alike, so the
# outcome is read from what it prints. Anything else is "error", which matches
# no expectation: a model that fails to load must not satisfy a "violated" row.
check() { # instance invariant expected(holds|violated)
    if [ "$MODE" = verify ]; then
        # A counterexample from the simulator is already conclusive.
        [ "$3" = holds ] || return 0
        out=$(npx quint verify ring_token_lock.qnt --main="$1" --invariant="$2" \
            --max-steps="$MAX_STEPS" --apalache-config=apalache.json 2>&1) || true
    else
        out=$(npx quint run ring_token_lock.qnt --main="$1" --invariant="$2" \
            --max-steps="$MAX_STEPS" --max-samples="$SAMPLES" 2>&1) || true
    fi
    case "$out" in
        *"Invariant violated"*|*"Found an issue"*) got=violated ;;
        *"No violation found"*) got=holds ;;
        *) got=error ;;
    esac
    if [ "$got" = "$3" ]; then
        printf 'ok    %-12s %-24s %s\n' "$1" "$2" "$got"
    else
        printf 'FAIL  %-12s %-24s expected %s, got %s\n' "$1" "$2" "$3" "$got"
        [ "$got" = error ] && printf '%s\n' "$out" | tail -3 | sed 's/^/      /'
        failed=1
    fi
}

# `current` must violate: it models a sidecar that does not inherit the lock.
check current      lockedWritersExclusive violated
check orphanFixed  lockedWritersExclusive holds
check allFixed     lockedWritersExclusive holds

# Whole token-writer set, including the unlocked `auth` login.
check current      mutualExclusion        violated
check orphanFixed  mutualExclusion        violated
check allFixed     mutualExclusion        holds

# The page: someone presented a rotated-away refresh token (assumption A1).
check current      noInvalidGrant         violated
check orphanFixed  noInvalidGrant         violated
check allFixed     noInvalidGrant         holds

exit "$failed"
