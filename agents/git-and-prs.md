# Git and PR flow

Part of the agent guide: [AGENTS.md](../AGENTS.md).

- Feature branches: `<gh-username>/feature-name`. Never work on `main`.
- Always `git fetch origin && git pull origin main` before creating a branch. Merging stale local `main` is the most common source of avoidable conflicts.
- Commit messages: conventional prefix (`feat:`, `fix:`, `docs:`, `refactor:`, `chore:`) enforced by pre-commit hook.
- **Never bypass pre-commit hooks** (`--no-verify`) unless the hook itself is broken (rare) — investigate the underlying failure. If hooks conflict with staged changes on ruff auto-fix, run `uv run ruff format` manually first, then re-stage.
- **PR review comment threads**: read → fix → push → reply *inside each thread* → resolve thread. `gh pr comment` alone is not the right tool — reviewers won't see the reply attached to their concern. Reply with `gh api repos/abutala/homely-vibes/pulls/<N>/comments/<comment_id>/replies -f body='…'`, then resolve with the GraphQL `resolveReviewThread(input: {threadId: …})` mutation (thread ids from `pullRequest.reviewThreads`) once the reply has returned an id.
- **Merge gate** (repository rulesets, so the classic branch-protection API returns 404; inspect with `gh api repos/abutala/homely-vibes/rules/branches/main`): a PR is required, squash merge only, every review thread must be resolved, 0 approvals required, and the `lint`, `test`, `review` and `security-scan` checks must pass. `main` also forbids deletion, force-push and non-linear history. There are no bypass actors — `gh pr merge --admin` does not get past it. Babysit the PR to `MERGED`: once every check is green and every thread is resolved, merge with a bare `gh pr merge <N> --squash`. Never arm `--auto` — it returns at once, so an armed PR reads as landed while it sits blocked on an open thread or a conflict with nobody watching.
- **A green `review` check does not mean "no issues".** The bot reviewer posts its findings as inline threads and the check still passes; it goes red only when no review was produced. Read the threads on the latest commit — the clean verdict is its "no issues found in commit `<sha>`" comment.
- **`security-scan` reads every blob a PR adds, not the diff.** A bad string (a real inbox, a denylisted term) anywhere in a file fails every PR that touches that file, and a follow-up commit cannot clear it because the blob stays in the PR's range. Placeholders use `example.com`; check for a placeholder before assuming a real leak. To clean a branch: `git reset --soft origin/main`, recommit from the corrected tree, `git push --force-with-lease`.
- **History starts 2026-08-30.** The repo was re-created without history, so PR and issue numbers restarted at #1. Older references are written `homely-vibes-archived#N` and point at a private archive — never resolve them against this repo.

## Hooks and code quality

Run `make setup` once in the primary checkout so the environment and hooks are consistent, and `make test` before pushing.

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
