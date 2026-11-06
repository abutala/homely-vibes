# MergeQueueBar Logbook

What was learned the hard way. Usage: [README.md](README.md).

## 2026-11-05: first build

- **`gh` by absolute path.** An app opened from Finder or `open` gets
  launchd's PATH (`/usr/bin:/bin:/usr/sbin:/sbin`), which has no Homebrew.
  `GitHubClient.ghCandidates` lists the paths to try.
- **`gh api graphql` exits 1 on a GraphQL error but prints the `errors` body
  on stdout.** The runner hands a non-empty stdout to the decoder, so the
  dropdown shows GitHub's message, not a bare exit code.
- **Search dates carry the offset.** A bare `merged:>=2026-11-05` leaves the
  time zone to GitHub. The query sends `2026-11-05T00:00:00-08:00`, so
  "today" is local; verified live against the landed count on 2026-11-05.
- **The title can sit behind a menu bar manager.** A new status item appears
  leftmost; with Hidden Bar (or Bartender) it starts hidden behind the
  chevron. Drag it right of the divider.
