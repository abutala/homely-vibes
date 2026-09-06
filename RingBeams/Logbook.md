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

---

## Landmines

### `NODE_PATH` will not rescue a missing `node_modules`

Setting `NODE_PATH` will **not** rescue this. `fetch_status.js` is `"type": "module"`,
and per [Node's ESM docs](https://nodejs.org/api/esm.html) *"`NODE_PATH` is not part of
resolving `import` specifiers"* -- it applies only to CommonJS `require()`. Only a real
`node_modules/` on the resolution walk works.

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
