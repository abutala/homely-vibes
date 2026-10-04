#!/bin/sh
# Pins what Quint's randomized simulator must (not) find in ring_token_lock.qnt.
# A flipped result in either direction fails: a "holds" row that now violates is
# a regression; a "violated" row that now holds means the model stopped
# reproducing the bug it documents. This is search, not proof: see README.md.
set -eu
cd "$(dirname "$0")"

SAMPLES="${QUINT_SAMPLES:-200000}"
failed=0

check() { # instance invariant expected(holds|violated)
    if npx quint run ring_token_lock.qnt --main="$1" --invariant="$2" \
        --max-steps=20 --max-samples="$SAMPLES" >/dev/null 2>&1; then
        got=holds
    else
        got=violated
    fi
    if [ "$got" = "$3" ]; then
        printf 'ok    %-12s %-24s %s\n' "$1" "$2" "$got"
    else
        printf 'FAIL  %-12s %-24s expected %s, got %s\n' "$1" "$2" "$3" "$got"
        failed=1
    fi
}

# Sidecar orphaned by a killed parent: the bug this model was written for.
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
