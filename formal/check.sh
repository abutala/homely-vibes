#!/bin/sh
# Pins what Quint's randomized simulator must (not) find in the models here,
# row by row from outcomes.txt. A flipped result in either direction fails: a
# "holds" row that now violates is a regression; a "violated" row that now holds
# means the model stopped reproducing the bug it documents. This is search, not
# proof: verify.sh is the exhaustive counterpart.
set -eu
cd "$(dirname "$0")"

SAMPLES="${QUINT_SAMPLES:-200000}"
failed=0

# Quint exits 1 for a counterexample and for a broken model alike, so the
# outcome is read from what it prints. Anything else is "error", which matches
# no expectation: a model that fails to load must not satisfy a "violated" row.
check() { # instance invariant expected(holds|violated)
    model=$(model_of "$1"); steps=$(steps_of "$model")
    out=$(npx quint run "$model" --main="$1" --invariant="$2" \
        --max-steps="${steps:-20}" --max-samples="$SAMPLES" 2>&1) || true
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

# A row's model is the file whose module declares its instance; its step bound
# is that file's `// max-steps: N` line (default 20).
model_of() { grep -l "^module $1 " ./*.qnt | head -1; }
steps_of() { sed -n 's#^// max-steps: *\([0-9]*\).*#\1#p' "$1" | head -1; }

rows=$(mktemp)
trap 'rm -f "$rows"' EXIT
grep -v '^#' outcomes.txt | grep -v '^$' > "$rows"
while read -r instance invariant expected; do
    check "$instance" "$invariant" "$expected"
done < "$rows"

exit "$failed"
