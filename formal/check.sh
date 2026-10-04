#!/bin/sh
# Pins what Quint's randomized simulator must (not) find in ring_token_lock.qnt.
# A flipped result in either direction fails: a "holds" row that now violates is
# a regression; a "violated" row that now holds means the model stopped
# reproducing the bug it documents. This is search, not proof: see README.md.
set -eu
cd "$(dirname "$0")"

SAMPLES="${QUINT_SAMPLES:-200000}"
failed=0

# Quint exits 1 for a counterexample and for a broken model alike, so the
# outcome is read from what it prints. Anything else is "error", which matches
# no expectation: a model that fails to load must not satisfy a "violated" row.
check() { # instance invariant expected(holds|violated)
    out=$(npx quint run ring_token_lock.qnt --main="$1" --invariant="$2" \
        --max-steps=20 --max-samples="$SAMPLES" 2>&1) || true
    case "$out" in
        *"Invariant violated"*) got=violated ;;
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
