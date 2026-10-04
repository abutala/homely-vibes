// Self-timeout for the sidecar (ESM, dependency-free so it is testable alone).
//
// beams_manager.run_sidecar enforces sidecar_timeout_seconds from the parent,
// but the sidecar inherits the Ring token flock so that a hard-killed parent
// cannot leave it refreshing outside the lock. An orphan has no parent left to
// time it out, so it must bound itself, or a hang would hold the lock forever.
//
// RING_BEAMS_TIMEOUT_S unset or non-positive disables it. Exits 4 (see the
// exit-code contract in fetch_status.js). unref() keeps the timer from holding
// an otherwise finished process open.
export function armWatchdog(env = process.env, exit = process.exit) {
    const seconds = Number(env.RING_BEAMS_TIMEOUT_S);
    if (!(seconds > 0)) return;
    setTimeout(() => {
        console.error(JSON.stringify({ error: `sidecar watchdog: exceeded ${seconds}s` }));
        exit(4);
    }, seconds * 1000).unref();
}
