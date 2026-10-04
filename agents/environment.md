# Development environment

Part of the agent guide: [AGENTS.md](../AGENTS.md).

**Package Manager**: This project uses `uv` for fast Python dependency management.

**Worktree venv**: Git worktrees share the primary checkout's `.venv`. Worktrees
don't get their own `.venv` (uv won't sync there due to cache permission issues
and networkless sandboxes), so tests run against the primary interpreter.

Ask git where that checkout is instead of hardcoding a path — `--git-common-dir`
resolves to the shared `.git` from the primary checkout *and* from any worktree,
so the same two lines work on every machine:

```bash
HV=$(dirname "$(git rev-parse --path-format=absolute --git-common-dir)")

# From any worktree:
VIRTUAL_ENV="$HV/.venv" "$HV/.venv/bin/python" -m pytest [args]

# NodeCheck runs in isolation (matches `make test`):
VIRTUAL_ENV="$HV/.venv" "$HV/.venv/bin/python" -m pytest NodeCheck
```

If tests fail with `PermissionError` on the log directory, create a temporary
`config/local.yaml` pointing `logging_dir` at a writable path (e.g. `/tmp/hv-logs`)
and remove it before committing:

```yaml
# config/local.yaml (temporary, gitignored -- do not commit)
paths:
  home: /tmp
  logging_dir: /tmp/hv-logs
```

**Every worktree fails with `fatal: this operation must be run in a work tree`**:
the primary checkout is a normal (non-bare) repo with `extensions.worktreeConfig=true`,
so `core.bare=true` in its shared `.git/config` breaks every linked worktree.
Signature: `git rev-parse --git-dir` still resolves while `--is-inside-work-tree`
prints `false`. `git worktree list` then shows the primary as `(bare)` — that is the
bad config talking, not evidence the repo is bare. Recover from the primary checkout:

```bash
cd "$HOMELY_VIBES"
git config --list --local | grep -E '^core\.bare=true|^core\.worktree|^user\.'   # expect no output
git config core.bare false                                    # only if it read true
git config --unset core.worktree                              # stray value pointing at a test tmp dir
git config --unset user.name; git config --unset user.email   # identity falls back to ~/.gitconfig
```

The usual cause is a test running real `git` under a hook that exported `GIT_DIR`
(see `AppleNotesBackup/Logbook.md`). **Never export `GIT_DIR`/`GIT_WORK_TREE` to work
around git discovery** — they leak into hook subprocesses and cause exactly this.

**Development Setup** (primary checkout):
```bash
make setup  # Installs Python 3.13.7, dependencies, Git submodules, and pre-commit hooks
```

**Common Commands**:
```bash
# Development workflow
make test           # Run all tests with pytest
make lint           # Run all linters (ruff, mypy, vulture, semgrep, codespell, deptry)
make hooks          # Set up pre-commit hooks
make clean          # Clean build artifacts and caches

# Individual tools
make ruff           # Code formatting and fixes
make mypy           # Type checking
make vulture        # Dead code detection
make semgrep        # Security analysis
make deptry         # Dependency analysis
make codespell      # Spell checking

# Test coverage
make coverage       # Run tests with coverage report
make coverage-html  # Generate HTML coverage report and open in browser
make coverage-lcov  # Generate lcov coverage report

# Docker environment (if needed)
make colima         # Start colima Docker environment with disk space checks

# Run specific modules
uv run python Tesla/manage_power_clean.py
uv run python RachioFlume/rfmanager.py
uv run python August/august_manager.py monitor
uv run python SamsungFrame/manage_samsung.py status
```

`make lint` rewrites files: `ruff check --fix`, `ruff format` and `codespell -w` can
touch files unrelated to your change, and pre-commit can sweep those edits into your
commit. Run `git diff --stat` afterwards and revert anything you did not intend. A
real identifier codespell mangles belongs in `[tool.codespell] ignore-words-list` in
`pyproject.toml`.
