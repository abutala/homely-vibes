# MergeQueueBar Logbook

What was learned the hard way. Usage: [README.md](README.md).

## 2026-11-05: first build

- **`gh` by absolute path.** An app opened from Finder or `open` gets
  launchd's PATH (`/usr/bin:/bin:/usr/sbin:/sbin`), which has no Homebrew.
  `GitHubClient.ghCandidates` lists the paths to try.
- **`gh api graphql` exits 1 on a GraphQL error but prints the `errors` body
  on stdout.** So does an HTTP error (`{"message":"Bad credentials"}`). The
  runner hands a non-empty stdout to the decoder, which reads either shape,
  so the dropdown shows GitHub's message, not a bare exit code.
- **A bounce keeps `ready to review`.** The lander adds `automerge failed`
  and leaves the queue label, so the queue search must exclude it, or a
  bounced PR counts twice (tagged and failed).
- **Search dates carry the offset.** A bare `merged:>=2026-11-05` leaves the
  time zone to GitHub. The query sends `2026-11-05T00:00:00-08:00`, so
  "today" is local; verified live against the landed count on 2026-11-05.
- **The title can sit behind a menu bar manager.** A new status item appears
  leftmost; with Hidden Bar (or Bartender) it starts hidden behind the
  chevron. Drag it right of the divider.
- **Cost.** Searches in one GraphQL query are not priced one point each:
  17 searches cost 2 points, and so do 7 (`rateLimit{cost}` on the query).

## 2026-11-06: count every PR of mine

- **`-label:autolanded` hid most of my merges.** The lander merges most of
  my PRs, so "my merged today" showed 7 of 18. `Me` now counts every PR I
  authored; only the dropdown list leaves my queued PRs to the queue list,
  so no PR shows twice.
- **`✗N` sat after `Me`**, so it read as mine. It is the queue's bounce
  count: it is now `(⚠︎N)` right after `MQ`, counts every open bounced PR
  at any age, and stays out of the MQ total. The `⚠︎` carries U+FE0E so the
  menu bar draws the text glyph, not the colour emoji.
