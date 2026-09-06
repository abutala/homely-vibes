# lib — Logbook

Learnings and landmines. How to use this module: [README.md](README.md).

---

## Conventions

- **No `patch()` in tests.** Refactor production code to accept the dependency as a parameter (factory or client). Inject fakes that satisfy a `Protocol` or duck-type the surface.
- **Secrets live in `config/tokens/`** (symlinked to `~/bin/Common-configs/tokens/`, gitignored). Config values in `config/local.yaml` (gitignored).
- **New module config → dataclass in `config.py` + default.yaml block.** Never ad-hoc `get()`.

---

## Design rationale

### `lib/TeslaPy/` — a legacy SDK we still carry

`lib/TeslaPy/` is a legacy Tesla SDK, kept as a git submodule and excluded from linting. The Tesla module now talks to the Fleet API instead, but the submodule is retained for history.
