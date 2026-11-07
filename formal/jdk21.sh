# Sourced by check.sh and verify.sh. use_jdk21 exports JAVA_HOME for a JDK 21
# or newer, or returns 1: Apalache and TLC as Quint downloads them need class
# file version 65.
jdk_major() {
    m=$("$1/bin/java" -version 2>&1 | sed -n 's/.*version "\([0-9]*\).*/\1/p' | head -1)
    echo "${m:-0}"
}

use_jdk21() {
    for candidate in "${JAVA_HOME:-}" \
        "$(/usr/libexec/java_home -v 21 2>/dev/null || true)" \
        /opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home; do
        if [ -n "$candidate" ] && [ -x "$candidate/bin/java" ] \
            && [ "$(jdk_major "$candidate")" -ge 21 ]; then
            JAVA_HOME="$candidate"
            export JAVA_HOME
            return 0
        fi
    done
    echo "needs JDK 21 or newer (macOS: brew install openjdk@21), or JAVA_HOME pointing at one." >&2
    return 1
}
