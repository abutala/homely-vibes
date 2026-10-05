# Scheduling and deployment

Part of the agent guide: [AGENTS.md](../AGENTS.md).

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
- **Never run `make setup` on the prod host** — deploy with `uv sync` (plus `make node-deps`). `setup` also runs `git submodule update` and `make hooks`, and the hooks run the full test suite on every commit, which a deploy host has no use for. (`brew-deps` itself already skips off macOS.)
