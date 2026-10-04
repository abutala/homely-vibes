# RingBeams — Logbook

Learnings and landmines. How to use this module: [README.md](README.md).

---

## Incidents

### 2026-08-30 — Missing `node_modules` on the prod host

`node_modules/` is gitignored, so **any fresh clone or re-clone has a working Python
side and no sidecar deps at all**. This bit the prod host on 2026-08-30: the checkout
was replaced, the untracked directory went with it, and `git pull && uv sync` has no
step that brings it back. Node then died at module load and its
`ERR_MODULE_NOT_FOUND` stack became the Pushover body.

`beams_manager` now pre-flights for the package and raises a one-line remedy instead.
Fix is always `make node-deps`.

### 2026-10-04 — A killed parent orphaned the sidecar outside the token lock

Found by modelling the callers ([formal/Logbook.md](../formal/Logbook.md)), then
reproduced with a real `SIGKILL`. `beams_manager` held the token flock across the Node
sidecar, but the sidecar never held it: flock is released when its holder dies, so a
parent killed mid-run (OOM, cron kill) left a live sidecar rotating the refresh token
while RingSecurity took the free lock. Ring rotates on every use, so the loser gets
`invalid_grant`. Not observed in production; the cost would have been a spurious
"Ring: Auth Required" and a re-auth.

Fix: `acquire_lock` yields its fd and `run_sidecar` passes it via `pass_fds`, so the
sidecar shares the open file description and the lock lives until the last holder exits.
Because that makes a hung orphan hold the lock indefinitely, with no parent left to
enforce `sidecar_timeout_seconds`, the sidecar now arms `watchdog.js` and exits 4 on
the same budget. A hung orphan therefore ends in at most that long, not a permanent
"Ring: Token Lock Timeout" P1 on every run.

---

## Landmines

### The lock must be released with `close()`, never `LOCK_UN`

With the sidecar sharing the lock's open file description, an explicit `LOCK_UN` in the
parent releases it for the sidecar too. `acquire_lock` only closes its fd.

### `NODE_PATH` will not rescue a missing `node_modules`

Setting `NODE_PATH` will **not** rescue this. `fetch_status.js` is `"type": "module"`,
and per [Node's ESM docs](https://nodejs.org/api/esm.html) *"`NODE_PATH` is not part of
resolving `import` specifiers"* -- it applies only to CommonJS `require()`. Only a real
`node_modules/` on the resolution walk works.

### The dependency preflight must run *after* the token check

`run_sidecar` checks for the token file before `_require_sidecar_deps()`. Reversed, a
missing token reports "run `make node-deps`" instead of `BeamsAuthError` -> P0
"Ring: Auth Required", sending you after the wrong problem. Local runs cannot catch a
regression here: with `node_modules` installed the preflight never fires. CI has no
`node_modules`, so `test_missing_token_raises_auth_error` is where the ordering is
actually exercised.

### `npm WARN EBADENGINE` on Node 25 is noise

`ring-client-api@14.3.0` declares `"node": "^20 || ^22 || ^24"`. On Node 25 npm warns
and installs anyway, and the sidecar runs normally there. Don't downgrade Node to
silence it.

---

## Error reference

### `ERR_MODULE_NOT_FOUND` from the sidecar

Sidecar deps were never installed, or were lost with a re-clone:

```bash
make node-deps 2>&1 | tee /tmp/ring_beams_node_deps.log
```

---

## References

- Node ESM resolution (`NODE_PATH` is CommonJS-only): https://nodejs.org/api/esm.html
- `ring-client-api` (dgreif/ring), the sidecar's socket.io client: https://github.com/dgreif/ring
