# Practices

Part of the agent guide: [AGENTS.md](../AGENTS.md).

Non-obvious rules that repeat across modules. Adhere to these in new code and PR reviews.

## Module docs: README is usage, Logbook is learnings

Every module carries two documents, and content belongs to exactly one of them.

- **`README.md` — how to use it.** What it does, setup, CLI commands, config
  reference, examples, testing. A reader who wants to *run* the thing should
  never have to scroll past a war story to find the command.
- **`Logbook.md` — what we learned the hard way.** Dated incidents, landmines,
  "why we chose X over Y", options considered and rejected, troubleshooting and
  error references, known limitations.

The split exists because the two rot differently: usage docs must track the
code, while a logbook is append-mostly and its value grows with age. Mixing
them means the incident writeup gets deleted during a routine usage edit.

When you fix a non-obvious bug, add the entry to `Logbook.md` in the same
commit as the fix. `Tesla/Logbook.md` is the reference for tone and structure.

## Secrets on disk
- **Never `open(path, "w")` for a secret**, and never `write_text()` + `chmod`. Both leave a TOCTOU window at 0o644 under a 0o022 umask. Use `lib.secure_io.write_secret_atomic()` — it opens with `O_CREAT|O_TRUNC|0o600` so the file is world-unreadable from birth.
- If a **third-party library** writes the token (yalexs, SamsungTVWS, ring-client-api Node), immediately call `ensure_secret_perms(path)` after the call returns.
- Config files themselves live in `config/local.yaml` (gitignored). Tokens live under `config/tokens/` (symlinked to `~/bin/Common-configs/tokens/`, also gitignored on the code side).

## macOS Keychain (native apps)
- **Own the item you read.** Reading a Keychain item another app writes cannot be made durable: the owner's rewrites reset both access lists. Create your own item (`com.deviationlabs.<App>`) and treat the foreign item as a one-time bootstrap source only. This is what Chrome/Slack/Cursor all do — one ACL entry, `teamid:` partition.
- **A read is gated by TWO lists**: the ACL application list *and* the partition list. `codesign -d -r-` only tells you about the first. Inspect the second with `security dump-keychain -a`; `teamid:` is stable across rebuilds, `cdhash:` is not.
- **`cdat` vs `mdat`** on an item reveals who rewrites it — a moving `mdat` under a fixed `cdat` means another process owns the write path.
- To read a foreign item without a consent prompt, shell out to `/usr/bin/security`: it carries `apple-tool:`, which survives the owner's rewrites. Pipe the secret back — never through `argv`, never to disk.

## Alert priority discipline (Pushover)
Convention: `P{N}` maps 1:1 to Pushover `priority=N`. Every module README uses this scheme — the number IS the priority value, not a semantic tier.

- **P-1 (`priority=-1`)** — silent (no sound/vibration). Zone-end reports, informational clears, "act when convenient." Default for anything that doesn't need to interrupt.
- **P0 (`priority=0`)** — normal (default sound). Recovery/"cleared" transitions after a fire, non-urgent status change.
- **P1 (`priority=1`)** — high (bypasses quiet hours). Actionable within hours: low battery, service unreachable, hardware failure, partial sidecar failure, degraded network link.
- **P2 (`priority=2`)** — emergency (retries until acked). Reserve for water leaks, break-ins, sustained-flow rules firing — things where seconds matter. Don't cry wolf.
- **Auth failures land at P0**, not P1 or P2. Re-auth is a chore, not an emergency, but shouldn't be silent.

## Sidecars & polyglot integration
- Node sidecars live inside the Python module (e.g., `RingBeams/fetch_status.js` alongside `beams_manager.py`).
- `node_modules/` is gitignored per-module; commit only `package.json` + `package-lock.json`.
- **A gitignored `node_modules/` is a deploy-time dependency.** `git pull` never restores it, so any fresh clone or re-clone leaves a working Python side and no sidecar. Run `make node-deps` after any re-clone, and give the Python parent a preflight check so the failure reads as "run make node-deps" rather than a Node stack trace in an alert body (`RingBeams/beams_manager.py::_require_sidecar_deps`).
- `NODE_PATH` does not apply to ESM sidecars — it is CommonJS-only ([Node docs](https://nodejs.org/api/esm.html)). Only a real `node_modules/` on the resolution walk works.
- Sidecar exit-code contract must be explicit and documented at the top of the sidecar file. Python maps codes to Python exception classes; overloading `exit 1` for both auth failure and generic errors is the classic misclassification bug.
- Drain stdout before `process.exit(0)` — pass the exit callback to `process.stdout.write(payload, () => process.exit(0))`. On stdout-as-pipe, writes above ~16KB are buffered.
- Surface partial failures (per-location, per-device) in the JSON payload, not just stderr. Python only reads stderr on non-zero exit, so a silent partial with `exit 0` becomes a false "all healthy" report.
