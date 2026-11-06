# MergeQueueBar

Gotchas and learnings: [Logbook.md](Logbook.md).

A macOS menu bar app that shows today's pr-lander merge queue (MQ) and
your own PRs that the lander does not handle:

```
MQ 1/29 · Me 1/12 ✗1
```

- **`MQ tagged/total`**: PRs in the queue now (label `ready to review`, not
  bounced, not `nomerge`) / every PR the queue held today (still tagged +
  landed today + failed today). Scoped to one org.
- **`Me open/total`**: your open PRs in every repo, without the ones in the
  queue / those + yours merged today without `autolanded`. A bounced or
  `nomerge` PR counts as yours: the lander is not handling it.
- **`✗N`**: shown only when N PRs bounced today (label `automerge failed`).

The dropdown:

```
Merge queue: 1 tagged · 28 landed · 0 failed today
  ▶ repo#50 Title…                        ← ▶: the lander is on it now
Failed today (N)                          ← only when N > 0
My PRs, not with MQ: 1 open · 11 merged today
  repo#69 Title… (draft)
Last 7d: MQ 92 landed (13/day) · Me 44 merged (6/day)
Open PRs on GitHub · My PRs on GitHub · Updated · Refresh · Refresh Every · Quit
```

The 7-day window starts at local midnight 6 days ago, so it includes today.
A click on a PR opens it; the two links open [github.com/pulls](https://github.com/pulls) and
[github.com/pulls/authored](https://github.com/pulls/authored).

No Dock icon (`LSUIElement`), no Xcode project: a Swift Package Manager
executable wrapped in a minimal `.app` bundle.

## How it counts

One `gh api graphql` call per refresh runs 7 GitHub searches. Days start at
local midnight, sent with their UTC offset. MQ searches add `org:<org>`.

| Number | Search |
|---|---|
| Tagged | `is:pr is:open label:"ready to review" -label:"automerge failed" -label:nomerge` |
| Landed today | `is:pr is:merged label:autolanded merged:>=<midnight>` |
| Failed today | `is:pr is:open label:"automerge failed" updated:>=<midnight>` |
| My open | `is:pr author:@me is:open`, then the app drops the PRs in the queue |
| My merged today | `is:pr author:@me is:merged -label:autolanded merged:>=<midnight>` |
| Last 7d | the landed and my-merged searches with `merged:>=<midnight 6 days ago>` |

GitHub search cannot filter on the time a label was added, so "failed today"
means an open, bounced PR that changed today. Counts come from GitHub's
`issueCount`. The queue and failed lists show at most 50 PRs and then
`… and N more`; my open list holds 100, so its count is exact up to 100.

**API cost**: the whole query costs 2 GraphQL points (`rateLimit{cost}`, 2026-11-05),
from the 5,000 points an hour your account gets. A 2-minute refresh uses 60
points an hour; a 1-minute refresh, 120.

## Setup

Needs the GitHub CLI, signed in: `brew install gh`, then `gh auth login`.
The org defaults to `mastrix-ai`. To change it:

```bash
defaults write com.deviationlabs.MergeQueueBar org <your-org>
```

## Build and install

```bash
swift test                              # unit tests
swift run MergeQueueBar --probe         # one fetch, printed; no menu bar
./Scripts/build_app.sh --install        # release build → /Applications, relaunch
```

To start it at login, add `/Applications/MergeQueueBar.app` in System
Settings → General → Login Items.

## Refresh

Every 2 minutes by default. Change it from the dropdown (1, 2, 5 or 10 min);
the choice is kept in `UserDefaults`. A failed refresh keeps the last good
numbers, adds `↻` to the title and shows the reason in the dropdown.

Logs: `log stream --predicate 'subsystem == "com.deviationlabs.MergeQueueBar"' --info`.
