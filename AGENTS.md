# AGENTS.md

Guidance for coding agents working in this repository. `CLAUDE.md` is a symlink to this file.

This file is the index and the rules that apply to every change. The detail lives in
[agents/](agents/), one topic per file: read the one that matches the task before starting it.

## What this repo is

A modular home-automation system: independent modules (one directory each) over a shared `lib/`
(config, logging, notifications, secret I/O, file lock). Python 3.13 managed with `uv`; a few
modules are Swift or TypeScript. Each module has a `README.md` (how to use it) and a `Logbook.md`
(what was learned the hard way).

## Read before you touch

| Task | Read |
|---|---|
| Running anything: venv, worktrees, `make` targets, a broken worktree | [agents/environment.md](agents/environment.md) |
| Finding your way: modules, shared patterns, dependencies | [agents/architecture.md](agents/architecture.md) |
| Reading or adding config keys | [agents/configuration.md](agents/configuration.md) |
| Writing or running tests | [agents/testing.md](agents/testing.md) |
| Working in a specific module | [agents/modules.md](agents/modules.md), then that module's `README.md` and `Logbook.md` |
| Secrets, Keychain, alert priorities, sidecars, where docs go | [agents/practices.md](agents/practices.md) |
| Cron, the prod host, deploying | [agents/deployment.md](agents/deployment.md) |
| Branching, commits, hooks, review threads, the merge gate | [agents/git-and-prs.md](agents/git-and-prs.md) |

## Rules that apply to every change

- **Never `patch()` production code in a test.** Take the dependency as a parameter instead
  ([testing](agents/testing.md)).
- **Secrets on disk go through `lib.secure_io`**, never `open(path, "w")`
  ([practices](agents/practices.md)).
- **Config is typed.** Add a dataclass in `lib/config.py` and a placeholder in
  `config/default.yaml`; real values live in the gitignored `config/local.yaml`
  ([configuration](agents/configuration.md)).
- **No household identifiers in the repo**: device names, hostnames, addresses and real inboxes
  fail the security scan. Use neutral labels and `example.com`.
- **Usage goes in the module `README.md`, learnings in its `Logbook.md`**, and a non-obvious fix
  adds its Logbook entry in the same commit ([practices](agents/practices.md)).
- **Feature branches only, conventional commit subjects, never `--no-verify`**; a PR is merged by
  watching it to green with every thread resolved, never by arming auto-merge
  ([git and PRs](agents/git-and-prs.md)).
- **`make lint` rewrites files.** Check `git diff --stat` afterwards and revert what you did not
  intend ([environment](agents/environment.md)).
- **Never run `make setup` on the prod host** ([deployment](agents/deployment.md)).
