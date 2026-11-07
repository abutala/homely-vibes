#!/bin/sh
# Exhaustive counterpart of check.sh: Apalache (`quint verify`) over the same
# rows of outcomes.txt. A "holds" row here is a proof over every execution of
# the model; a "violated" row is a counterexample the solver constructed.
#
# MAX_STEPS must exceed the longest run of a model that sets no `// max-steps:` line. No actor acts twice, so a
# run is at most 12 steps (rs 4, bp 3, sc 3, au 2); 20 therefore covers every
# execution. Raise it whenever an action or actor is added.
#
# Needs JDK 21: the Apalache build Quint downloads is compiled for class file
# version 65. A model state with no enabled action before every actor finishes
# is reported as a deadlock and fails the row.
set -eu
cd "$(dirname "$0")"

MAX_STEPS="${QUINT_MAX_STEPS:-20}"

. ./jdk21.sh
use_jdk21 || exit 1

failed=0

# Same rule as check.sh: read the verdict from the output, never the exit code.
verify() { # instance invariant expected(holds|violated)
    model=$(model_of "$1"); steps=$(steps_of "$model")
    if [ "$(backend_of "$model")" = tlc ]; then
        out=$(npx quint verify "$model" --main="$1" --invariant="$2" --backend=tlc 2>&1) || true
    else
        out=$(npx quint verify "$model" --main="$1" --invariant="$2" \
            --max-steps="${steps:-$MAX_STEPS}" 2>&1) || true
    fi
    case "$out" in
        *"No violation found"*) got=holds ;;
        *"reached a deadlock"*) got=deadlock ;;
        *"found a counterexample"*) got=violated ;;
        *) got=error ;;
    esac
    if [ "$got" = "$3" ]; then
        printf 'ok    %-12s %-24s %s\n' "$1" "$2" "$got"
    else
        printf 'FAIL  %-12s %-24s expected %s, got %s\n' "$1" "$2" "$3" "$got"
        [ "$got" = holds ] || printf '%s\n' "$out" | tail -3 | sed 's/^/      /'
        failed=1
    fi
}

# A row's model is the file whose module declares its instance; its step bound
# is that file's `// max-steps: N` line (default 20). A `// backend: tlc` line
# runs TLC instead: it walks the whole finite state graph, so it needs no step
# bound, and it finishes models whose step bound Apalache cannot.
model_of() { grep -l "^module $1 " ./*.qnt | head -1; }
steps_of() { sed -n 's#^// max-steps: *\([0-9]*\).*#\1#p' "$1" | head -1; }
backend_of() { sed -n 's#^// backend: *\([a-z]*\).*#\1#p' "$1" | head -1; }

rows=$(mktemp)
trap 'rm -f "$rows"' EXIT
grep -v '^#' outcomes.txt | grep -v '^$' > "$rows"
while read -r instance invariant expected; do
    verify "$instance" "$invariant" "$expected"
done < "$rows"

exit "$failed"
