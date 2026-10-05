# lib — Logbook

Learnings and landmines. How to use this module: [README.md](README.md).

---

## Conventions

- **No `patch()` in tests.** Refactor production code to accept the dependency as a parameter (factory or client). Inject fakes that satisfy a `Protocol` or duck-type the surface.
- **Secrets live in `config/tokens/`** (symlinked to `~/bin/Common-configs/tokens/`, gitignored). Config values in `config/local.yaml` (gitignored).
- **New module config → dataclass in `config.py` + default.yaml block.** Never ad-hoc `get()`.

---

## Incidents

### 2026-10-04 — `write_secret_atomic` was atomic in permissions only

The helper opened the target with `O_TRUNC` and wrote in place, so a crash mid-write
left a truncated token file, while `file_lock.py` attributed a temp-file-and-rename
write to it and the README said the token file was rewritten that way. Nothing had tested the claim; a test that holds a reader
open across the write showed the reader seeing the new bytes. Not observed in production.

It now writes a `0o600` temp file in the same directory, fsyncs, and renames it over the
target. A symlinked path is resolved first so the link survives.

What changed for callers: the write needs write permission on the directory, not just
the file; the file always ends `0o600` and owned by the writer, which now includes the
August state file; and a hard kill between creating the temp file and the rename leaves
a `.<name>.<random>.tmp` beside the target holding the content. Keep that pattern
ignored wherever the token directory is version-controlled.
