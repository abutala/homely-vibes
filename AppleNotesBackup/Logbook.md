# AppleNotesBackup — Logbook

Learnings and landmines. How to use this module: [README.md](README.md).

---

## Landmines

### Why this design

- **AppleScript, not `NoteStore.sqlite`.** Notes are stored as gzip-compressed
  protobuf blobs in a private schema that changes across macOS versions. We go
  through Notes.app's scripting interface (`export_notes.applescript`) and read
  each note's rendered **HTML `body`** — lossless for text, lists, tables, and
  checklists, and stable across OS upgrades.
- **One HTML file per note, mirrored into git.** Each run makes the working tree
  match Notes exactly (deleting files for notes that vanished), then commits.
  Deleting the working file is safe — every past version stays in git history.
- **Hybrid filenames** `‹slug›__‹short_id›.html`. The `short_id` (an 8-hex-char
  fingerprint of the note's stable id) anchors identity, so renaming a note in
  Notes.app shows up as a git **edit**, not delete+add. Without it, every rename
  would look like an accidental delete and bury the real ones.

### Limitations (v1)

- **Attachments: metadata only.** Images, drawings, and scanned PDFs are recorded
  by count in each note's header comment but not exported as files. Full
  attachment export is future work.
- Runs on the Mac where Notes.app lives (notes are local); not a prod-host job.

### Real `git` in tests inherits the hook's `GIT_DIR`

Git exports `GIT_DIR`, `GIT_INDEX_FILE` and friends into every hook it runs
([githooks](https://git-scm.com/docs/githooks)), and the pre-commit hook runs
`make test`, so pytest inherits them. `GIT_DIR` outranks both `-C` and `cwd`: a
fixture's `git -C <tmp> config …` silently rewrites the developer's own
`.git/config` (seen: `core.bare` flipped to `true`, a stray `core.worktree`,
`user.name`/`user.email` overwritten), which then breaks every worktree — recovery
is in the root `CLAUDE.md` under Development Environment.

This is the only module that shells out to real git, so it carries two guards:
`conftest.py` scrubs the vars at import, and every git call here — production and
test — passes `env=git_env()`, so the tests do not depend on conftest for their own
safety.

To verify a change to either guard, aim the leaked vars at a throwaway canary, never
at a real repo, and expect passing tests and an empty diff:

```bash
C=$(mktemp -d) && git init -q "$C" && git -C "$C" config --list --local > "$C.before"
GIT_DIR="$C/.git" GIT_WORK_TREE="$C" uv run pytest AppleNotesBackup 2>&1 | tee /tmp/notes-backup-canary.log
git -C "$C" config --list --local | diff "$C.before" -
```

To prove the test-side guard alone, disable the `conftest.py` scrub for one run and
repeat.

---

## Error reference

### AppleScript error `-1728` on `container`

We read only *downward*; reading a folder/note's parent via `container` errors
(-1728) on items reached through a top-level collection.
