# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Environment

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

## Architecture Overview

### Module Organization
This is a **modular IoT home automation system** with independent components that share common utilities:

- **`lib/`**: Shared utilities (config, networking, notifications, logging, secret I/O, file lock)
- **Home / IoT modules**: August, NetworkCheck, NodeCheck, RachioFlume, RingBeams, RingSecurity, SamsungFrame, Tesla
- **AI / ML modules**: BimpopAI (RAG system), GarageCheck (computer vision), VoiceNotes (local STT)
- **Ops modules**: PersonalCalSync (Google Apps Script)
- **Client / adjacent**: NoShorts (iOS app), VSCodeSidebarNotes (VS Code / Cursor extension), BrowserAlert, GPXParser

### Key Architectural Patterns

**Shared Library Pattern**: All modules use utilities from `lib/`:
- `lib/config.py` - OmegaConf-based hierarchical YAML configuration system
- `lib/logger.py` - Standardized logging
- `lib/MyPushover.py`, `lib/Mailer.py` - Notification services
- `lib/NetHelpers.py` - Network utilities

**Independent Modules**: Each component directory (Tesla/, RachioFlume/, etc.) operates independently but follows consistent patterns:
- Main script with CLI interface
- README.md with component-specific documentation
- Test files following pytest conventions
- Pydantic models for data validation

**Git Submodules**: External dependencies like TeslaPy are managed as submodules in `lib/TeslaPy/`

## Configuration Management

**OmegaConf Config System**: This project uses OmegaConf with hierarchical YAML configuration:
- `config/default.yaml` - Safe defaults (checked into git)
- `config/local.yaml` - Secrets and overrides (gitignored)
- `lib/config.py` - Dataclass-based structured configs with type safety

**Configuration Access Pattern**:
```python
from lib.config import get_config

cfg = get_config()
email = cfg.tesla.powerwall_email
tokens = cfg.pushover.tokens["Powerwall"]
```

**Hot Reload Support** (for long-running processes):
```python
from lib.config import reset_config, get_config

reset_config()  # Clear cached config
cfg = get_config()  # Reload from YAML
```

**Initial Setup**: Create `config/local.yaml` with your overrides (only add values you want to change):
```yaml
tesla:
  powerwall_email: your@email.com
  powerwall_password: your_password

pushover:
  user: your_pushover_user
  tokens:
    Powerwall: your_token
```

Config merges default.yaml + local.yaml hierarchically.

## Testing Strategy

**Test Organization**:
- Tests are co-located with source files (e.g., `Tesla/test_manage_power.py`)
- Use pytest with asyncio support for async components
- Test paths configured in pyproject.toml: `["Tesla", "RachioFlume", "NodeCheck", "August", "SamsungFrame"]`
- **Note**: NodeCheck tests run in isolation (separate pytest invocation) due to subprocess management patterns

**Running Tests**:
```bash
# All tests
make test

# Specific module tests
uv run python -m pytest Tesla/test_manage_power.py -v
uv run python -m pytest August/test_august_client.py -v
uv run python -m pytest SamsungFrame/test_samsung_client.py -v

# Specific test class
uv run python -m pytest RachioFlume/test_integration.py::TestFlumeClient -v

# Specific test function
uv run python -m pytest Tesla/test_manage_power.py::test_powerwall_manager -v

# NodeCheck runs in isolation (uses pytest-forked)
uv run pytest NodeCheck
```

## Code Quality Standards

**Linting Pipeline**: Pre-commit hooks automatically run on every commit:
- `make ruff` - Code formatting and linting
- `make test` - Full test suite execution
- `.github/scripts/secret-scan.sh` - Secret scanning
- Conventional commit message format enforcement (e.g., `feat:`, `fix:`, `docs:`)
- `make setup` - post-merge hook: re-runs setup after every merge or `git pull`

**Type Checking**: mypy with strict configuration (Python 3.13 target)
**Security**: semgrep for security analysis, secret-scan.sh for credential detection

**Code Style**:
- ruff formatting (100 char line length)
- ruff for linting and import sorting
- Exclude `lib/TeslaPy/` from linting (external submodule)

## Component-Specific Guidance

### August Module (`August/`)
- **Authentication**: Requires 2FA via phone/email, tokens cached for ~7 days
- **Main Features**: Smart lock monitoring, unlock duration alerts, door ajar detection, battery warnings, lock failure detection
- **Initial Setup**: Run `august_manager.py test` to trigger 2FA, then use `validate_2fa.py` with verification code
- **Key Classes**: AugustManager with state persistence for alert tracking
- **Alert Thresholds**: Configurable via CLI (default: 5min unlock, 10min ajar, 20% battery)

### BimpopAI Module (`BimpopAI/`)
- **Architecture**: FastAPI backend + Streamlit frontend
- **Features**: RAG system with document indexing, conversational AI
- **Optional Dependencies**: Uses streamlit extra (`uv sync --extra streamlit`)

### ClaudeUsageBar Module (`ClaudeUsageBar/`)
- **Stack**: Swift Package Manager executable wrapped into a `.app` bundle (NOT Python — no uv, no pytest). Menu bar widget (`LSUIElement`, no Dock icon) showing Claude Code plan usage.
- **Build**: `swift build` for dev; `./Scripts/build_app.sh` for the signed `.app`. `swift test` runs the XCTest target.
- **Keychain**: owns its own item `com.deviationlabs.ClaudeUsageBar`; bootstraps from the `claude` CLI's item via `/usr/bin/security`. Never read the CLI's item with `SecItem` — see "macOS Keychain" under Best Practices.
- **Signing matters for correctness, not Gatekeeper**: `swift build` is ad-hoc (no team ID) so items it creates are `cdhash`-pinned and re-prompt; only the certificate-signed `.app` gets a stable `teamid:` partition entry.
- **Diagnostics**: `--probe-keychain` (which source served the token), `--probe-usage` (one-shot fetch). Neither ever prints a secret.

### lib/ (shared library)
- **Config**: All modules source configuration from `lib/config.py` (OmegaConf-based hierarchical YAML)
- **Notifications**: Standardized via MyPushover, Mailer, MyTwilio classes
- **Secret I/O**: `lib/secure_io.py` — `write_secret_atomic(path, content)` for tokens we own (0o600 from birth), `ensure_secret_perms(path)` after third-party library writes (yalexs, SamsungTVWS). **All token/credential writes must go through these.**
- **File lock**: `lib/file_lock.py` — POSIX `fcntl.flock` context manager for cross-process serialization on shared resources (e.g. Ring token file used by RingSecurity + RingBeams).
- **TeslaPy Submodule**: External dependency managed as Git submodule

### NodeCheck Module (`NodeCheck/`)
- **Purpose**: System node monitoring with continuous heartbeat tracking and automated device management
- **Testing**: Runs in isolation due to subprocess management patterns (uses pytest-forked)
- **Architecture**: Multi-process design requiring forked test execution to avoid state interference

### RachioFlume Module (`RachioFlume/`)
- **Integration**: Connects Rachio irrigation with Flume water monitoring
- **Architecture**: RachioClient, FlumeClient, WaterTrackingDB (SQLite), collector/reporter pattern
- **Usage**: `rfmanager.py` CLI with collect/status/report commands

### RingBeams Module (`RingBeams/`)
- **Purpose**: Daily battery + tamper health check for Ring Beams motion sensors and Ring Alarm sensors via Node sidecar (ring-client-api over socket.io).
- **Sidecar**: `fetch_status.js` — exit-code contract documented at top of file (0/1/2/3/4/5). Python parent maps 3 and 5 to `BeamsAuthError`; other non-zero codes raise `RuntimeError` (so a Node module-load crash never gets misclassified as "auth required").
- **Token sharing**: reads/writes the same `config/tokens/ring_auth_token.json` as RingSecurity; a POSIX flock (`lib.file_lock`) serializes the two runs so overlapping refreshes don't produce `invalid_grant`.

### RingSecurity Module (`RingSecurity/`)
- **Purpose**: Daily battery + offline health check for Ring cameras and doorbells via REST.
- **Authentication**: 2FA via `ring_manager.py auth`; token stored in `config/tokens/ring_auth_token.json`.
- **Token sharing**: see RingBeams — shared token, POSIX flock.

### SamsungFrame Module (`SamsungFrame/`)
- **Authentication**: WebSocket token-based auth, saved to `config samsung_frame.token_file`
- **Main Features**: Image upload to Frame TV, matte/border management, slideshow control, art inventory management
- **Initial Setup**: First upload command triggers TV pairing prompt, token auto-saved for future use
- **Key Classes**: SamsungFrameClient, UploadResult (Pydantic), ImageUploadSummary
- **CLI Commands**: upload, status, list-art, list-mattes, download-thumbnails, update-mattes, cycle-images
- **Image Requirements**: JPG/PNG format, <10MB, validated before upload

### Tesla Module (`Tesla/`)
- **Authentication**: Fleet API OAuth (previously TeslaPy — migrated in PR #178)
- **Main Features**: Powerwall monitoring, intelligent power management, battery history tracking, retry on transient Fleet API errors
- **Key Classes**: PowerwallManager, BatteryHistory, DecisionPoint, TeslaAPIClient

### VSCodeSidebarNotes Module (`VSCodeSidebarNotes/`)
- **Stack**: TypeScript VS Code / Cursor extension (NOT Python — does not use uv, pytest, or the rest of the repo's Python tooling).
- **Purpose**: Markdown sidebar that reads/writes `sidebar-notes.md` in the workspace root. Two-way sync with file watcher so Claude (or any external tool) can update the file and the sidebar refreshes live.
- **Build**: `cd VSCodeSidebarNotes && npm install && npm run compile` (esbuild → `dist/extension.js`). `npm run package-vsix` produces an installable `.vsix`.
- **Marketplace**: published under the `deviationlabs` publisher; see the module README for the publish flow.
- **Layout**: `package.json` (extension manifest), `src/` (TS source), `media/` (webview assets).

## Best Practices

Non-obvious rules that repeat across modules. Adhere to these in new code and PR reviews.

### Module docs: README is usage, Logbook is learnings

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

### Secrets on disk
- **Never `open(path, "w")` for a secret**, and never `write_text()` + `chmod`. Both leave a TOCTOU window at 0o644 under a 0o022 umask. Use `lib.secure_io.write_secret_atomic()` — it opens with `O_CREAT|O_TRUNC|0o600` so the file is world-unreadable from birth.
- If a **third-party library** writes the token (yalexs, SamsungTVWS, ring-client-api Node), immediately call `ensure_secret_perms(path)` after the call returns.
- Config files themselves live in `config/local.yaml` (gitignored). Tokens live under `config/tokens/` (symlinked to `~/bin/Common-configs/tokens/`, also gitignored on the code side).

### macOS Keychain (native apps)
- **Own the item you read.** Reading a Keychain item another app writes cannot be made durable: the owner's rewrites reset both access lists. Create your own item (`com.deviationlabs.<App>`) and treat the foreign item as a one-time bootstrap source only. This is what Chrome/Slack/Cursor all do — one ACL entry, `teamid:` partition.
- **A read is gated by TWO lists**: the ACL application list *and* the partition list. `codesign -d -r-` only tells you about the first. Inspect the second with `security dump-keychain -a`; `teamid:` is stable across rebuilds, `cdhash:` is not.
- **`cdat` vs `mdat`** on an item reveals who rewrites it — a moving `mdat` under a fixed `cdat` means another process owns the write path.
- To read a foreign item without a consent prompt, shell out to `/usr/bin/security`: it carries `apple-tool:`, which survives the owner's rewrites. Pipe the secret back — never through `argv`, never to disk.

### Alert priority discipline (Pushover)
Convention: `P{N}` maps 1:1 to Pushover `priority=N`. Every module README uses this scheme — the number IS the priority value, not a semantic tier.

- **P-1 (`priority=-1`)** — silent (no sound/vibration). Zone-end reports, informational clears, "act when convenient." Default for anything that doesn't need to interrupt.
- **P0 (`priority=0`)** — normal (default sound). Recovery/"cleared" transitions after a fire, non-urgent status change.
- **P1 (`priority=1`)** — high (bypasses quiet hours). Actionable within hours: low battery, service unreachable, hardware failure, partial sidecar failure, degraded network link.
- **P2 (`priority=2`)** — emergency (retries until acked). Reserve for water leaks, break-ins, sustained-flow rules firing — things where seconds matter. Don't cry wolf.
- **Auth failures land at P0**, not P1 or P2. Re-auth is a chore, not an emergency, but shouldn't be silent.

### Testing
- **Never `patch()` production code.** If a test needs to mock a subprocess/HTTP call, refactor the production code to accept the dependency as a parameter (factory or client). RingBeams's `run_sidecar(ring_factory=...)` is the reference pattern.
- **Module-level `cfg = get_config()` binds at import.** `get_config()` caches a singleton, so patching `get_config` after the module is imported changes nothing. Inject config as a parameter; if a legacy test must patch, patch the bound name (`module.cfg`), never the factory.
- **Test labels are neutral** (`"Controller"`, `"Zone A"`). Never copy a device name, zone label, or any other value from `config/local.yaml` into a test or fixture — those are household identifiers, and the CI denylist scan fails the PR on them.
- **Fake sidecars via `sh` scripts** for subprocess boundaries. `.chmod(0o755)` + write a shebang + parametrize exit codes and stdout. Zero mocking, real subprocess semantics. See `RingBeams/test_beams_manager.py`.
- **Separate deterministic assertions** (exact values, structural matches) from anything that depends on wall-clock time or network state. Freeze time via fixtures if needed.
- **NodeCheck runs in isolation** — pytest-forked to avoid subprocess state leak into other suites.

### Sidecars & polyglot integration
- Node sidecars live inside the Python module (e.g., `RingBeams/fetch_status.js` alongside `beams_manager.py`).
- `node_modules/` is gitignored per-module; commit only `package.json` + `package-lock.json`.
- **A gitignored `node_modules/` is a deploy-time dependency.** `git pull` never restores it, so any fresh clone or re-clone leaves a working Python side and no sidecar. Run `make node-deps` after any re-clone, and give the Python parent a preflight check so the failure reads as "run make node-deps" rather than a Node stack trace in an alert body (`RingBeams/beams_manager.py::_require_sidecar_deps`).
- `NODE_PATH` does not apply to ESM sidecars — it is CommonJS-only ([Node docs](https://nodejs.org/api/esm.html)). Only a real `node_modules/` on the resolution walk works.
- Sidecar exit-code contract must be explicit and documented at the top of the sidecar file. Python maps codes to Python exception classes; overloading `exit 1` for both auth failure and generic errors is the classic misclassification bug.
- Drain stdout before `process.exit(0)` — pass the exit callback to `process.stdout.write(payload, () => process.exit(0))`. On stdout-as-pipe, writes above ~16KB are buffered.
- Surface partial failures (per-location, per-device) in the JSON payload, not just stderr. Python only reads stderr on non-zero exit, so a silent partial with `exit 0` becomes a false "all healthy" report.

### Scheduling & deployment
- **macOS scheduled jobs live in Claude Code routines**, not in this repo. The former `LaunchJobs/` module (macOS `launchd` plist generator, incl. WhatsApp daily summary) was removed — routines replace it. Don't reintroduce a launchd module here; if you need a new scheduled Mac job, add a Claude Code routine.
- **`$HOMELY_VIBES` is the documented placeholder for the checkout root.** Docs and cron examples reference it rather than baking in one machine's path, because the checkout lives somewhere different on every host. Readers set it themselves, or derive it: `HOMELY_VIBES=$(dirname "$(git rev-parse --path-format=absolute --git-common-dir)")`. Never "fix" a placeholder by substituting a concrete path.
- **Linux prod host** stores homely_vibes at `~/Code` — so there `HOMELY_VIBES=~/Code`. That is the value, not a replacement for the variable; host-specific dirs that are *not* the checkout (`~/logs/`, `~/bin/Common-configs/`) stay literal.
- Cron entries redirect stdout+stderr to a file: `>> ~/logs/<script>.log 2>&1`. Never `> /dev/null` — you'd lose pre-logger crashes (import errors, `uv` failures, missing binaries).
- `lib.logger.get_logger()` sets up dual handlers (stdout + per-script log file under `cfg.paths.logging_dir`). Cron file redirection is the safety net for anything that happens before the logger initializes.
- Cron env needs `PATH` set for non-standard binaries (`node`, `uv`). Prepend `PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin` at the top of the crontab, or use absolute paths in commands.
- **Deploying to the prod host** after a PR merges — run on `<prod-host>`:
  ```bash
  cd "$HOMELY_VIBES" && git pull origin main && uv sync
  make node-deps   # only when RingBeams/ changed; needs npm on PATH (see the Makefile hint for nvm)
  ```
  Cron one-shots pick up new code on their next run. Long-running jobs started from `@reboot` under `run-one-constantly` (e.g. `Tesla/manage_power.py`, `NodeCheck/heartbeat_nodes.py`, `RachioFlume/rfmanager.py collect`) keep running the old code until their python process is killed — find it with `pgrep -af <script>` and kill the python child, not the wrapper; the wrapper respawns it. A plain `@reboot` job with no wrapper (e.g. `NetworkCheck/external_ip_reporter.py`) only picks up changes on the next reboot.
- **Never run `make setup` on the prod host** — deploy with `uv sync` (plus `make node-deps`). `setup` also runs `git submodule update` and `make hooks`, and once hooks are installed the post-merge hook re-runs `make setup` on every `git pull`. (`brew-deps` itself already skips off macOS.)

### Config changes
- Add a dataclass to `lib/config.py` for any new module's config, then register it in the root `Config` dataclass. Never `cfg_dict.get("your_key")` — the config system exists to give you type-checked access.
- `config/default.yaml` holds safe placeholders committed to git. `config/local.yaml` overrides with secrets and per-host values (gitignored, symlinked to `~/bin/Common-configs/Code_config_local.yaml`).
- If your module has multiple credentials, put them under a single top-level key (`ring:`, `august:`) so config diff reviews stay coherent.

### Git & PR flow
- Feature branches: `<gh-username>/feature-name`. Never work on `main`.
- Always `git fetch origin && git pull origin main` before creating a branch. Merging stale local `main` is the most common source of avoidable conflicts.
- Commit messages: conventional prefix (`feat:`, `fix:`, `docs:`, `refactor:`, `chore:`) enforced by pre-commit hook.
- **Never bypass pre-commit hooks** (`--no-verify`) unless the hook itself is broken (rare) — investigate the underlying failure. If hooks conflict with staged changes on ruff auto-fix, run `uv run ruff format` manually first, then re-stage.
- **PR review comment threads**: read → fix → push → reply *inside each thread* → resolve thread. `gh pr comment` alone is not the right tool — reviewers won't see the reply attached to their concern. Reply with `gh api repos/abutala/homely-vibes/pulls/<N>/comments/<comment_id>/replies -f body='…'`, then resolve with the GraphQL `resolveReviewThread(input: {threadId: …})` mutation (thread ids from `pullRequest.reviewThreads`) once the reply has returned an id.
- **Merge gate** (repository rulesets, so the classic branch-protection API returns 404; inspect with `gh api repos/abutala/homely-vibes/rules/branches/main`): a PR is required, squash merge only, every review thread must be resolved, 0 approvals required, and the `lint`, `test`, `review` and `security-scan` checks must pass. `main` also forbids deletion, force-push and non-linear history. There are no bypass actors — `gh pr merge --admin` does not get past it. Arm `gh pr merge <N> --squash --auto` and the PR lands once checks pass and threads are resolved.
- **A green `review` check does not mean "no issues".** The bot reviewer posts its findings as inline threads and the check still passes; it goes red only when no review was produced. Read the threads on the latest commit — the clean verdict is its "no issues found in commit `<sha>`" comment.
- **`security-scan` reads every blob a PR adds, not the diff.** A bad string (a real inbox, a denylisted term) anywhere in a file fails every PR that touches that file, and a follow-up commit cannot clear it because the blob stays in the PR's range. Placeholders use `example.com`; check for a placeholder before assuming a real leak. To clean a branch: `git reset --soft origin/main`, recommit from the corrected tree, `git push --force-with-lease`.
- **History starts 2026-08-30.** The repo was re-created without history, so PR and issue numbers restarted at #1. Older references are written `homely-vibes-archived#N` and point at a private archive — never resolve them against this repo.

## Development Workflow

1. **Start with setup**: `make setup` to ensure environment is consistent
2. **Pre-commit automation**: Pre-commit hooks automatically run `make ruff` and `make test` on every commit
   - Hooks also enforce conventional commit message format
   - Use `git commit -m "type: description"` format (e.g., `feat:`, `fix:`, `docs:`)
3. **Test locally**: `make test` before pushing changes
4. **Module isolation**: Each component can be developed independently
5. **Shared utilities**: Prefer extending `lib/` utilities over duplicating code

## Key Dependencies

- **Python 3.13+**: Required for async features and modern typing
- **uv**: Package manager for fast installs and dependency resolution
- **pydantic**: Data validation across all modules
- **pytest + asyncio**: Testing framework with async support
- **ruff + mypy**: Code quality and type checking