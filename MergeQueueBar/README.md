# MergeQueueBar

Gotchas and learnings: [Logbook.md](Logbook.md).

A macOS menu bar app that shows today's pr-lander merge queue (MQ) and
your own PRs:

```
MQ 1/29 (⚠︎1) Me 3/21
```

- **`MQ tagged/total`**: PRs in the queue now (label `ready to review`, not
  bounced, not `nomerge`) / those + landed today. Scoped to one org.
- **`(⚠︎N)`**: the open bounced PRs (label `automerge failed`), whatever day
  they bounced. Shown only when N > 0. Not in the MQ total.
- **`Me open/total`**: your open PRs in every repo / those + yours merged
  today. Both include the PRs the lander handles or merged.

The dropdown:

```
Merge queue: 1 tagged · 28 landed today · 1 failed
  ▶ repo#50 Title…                        ← ▶: the lander is on it now
Failed (N)                                ← only when N > 0
My PRs: 3 open, 1 in MQ · 20 merged today
  repo#69 Title… (draft)                  ← not the ones in MQ: they show once, above
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
| Failed | `is:pr is:open label:"automerge failed"` |
| My open | `is:pr author:@me is:open`; the dropdown list drops the PRs in the queue |
| My merged today | `is:pr author:@me is:merged merged:>=<midnight>` |
| Last 7d | the landed and my-merged searches with `merged:>=<midnight 6 days ago>` |

Counts come from GitHub's `issueCount`. The queue and failed lists show at
most 50 PRs and then `… and N more`. My open list holds 100, so `N in MQ` is
exact up to 100 open PRs.

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
