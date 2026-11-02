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

jdk_major() {
    m=$("$1/bin/java" -version 2>&1 | sed -n 's/.*version "\([0-9]*\).*/\1/p' | head -1)
    echo "${m:-0}"
}

found=""
for candidate in "${JAVA_HOME:-}" \
    "$(/usr/libexec/java_home -v 21 2>/dev/null || true)" \
    /opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home; do
    if [ -n "$candidate" ] && [ -x "$candidate/bin/java" ] \
        && [ "$(jdk_major "$candidate")" -ge 21 ]; then
        found="$candidate"
        break
    fi
done
if [ -z "$found" ]; then
    echo "verify.sh needs JDK 21 or newer (macOS: brew install openjdk@21), or JAVA_HOME pointing at one." >&2
    exit 1
fi
JAVA_HOME="$found"
export JAVA_HOME

failed=0

# Same rule as check.sh: read the verdict from the output, never the exit code.
verify() { # instance invariant expected(holds|violated)
    model=$(model_of "$1"); steps=$(steps_of "$model")
    out=$(npx quint verify "$model" --main="$1" --invariant="$2" \
        --max-steps="${steps:-$MAX_STEPS}" 2>&1) || true
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
# is that file's `// max-steps: N` line (default 20).
model_of() { grep -l "^module $1 " ./*.qnt | head -1; }
steps_of() { sed -n 's#^// max-steps: *\([0-9]*\).*#\1#p' "$1" | head -1; }

rows=$(mktemp)
trap 'rm -f "$rows"' EXIT
grep -v '^#' outcomes.txt | grep -v '^$' > "$rows"
while read -r instance invariant expected; do
    verify "$instance" "$invariant" "$expected"
done < "$rows"

exit "$failed"
