# MergeQueueBar

Gotchas and learnings: [Logbook.md](Logbook.md).

A macOS menu bar app that shows today's merge queue and your own PRs in one
GitHub org:

```
MQ 1/30 · Me 2/26 ✗1
```

- **`MQ tagged/total`**: PRs in the pr-lander queue now (label
  `ready to review`) / every PR the queue held today (still tagged + landed
  today + failed today).
- **`Me pending/total`**: your open PRs in the org / your open PRs + yours
  merged today.
- **`✗N`**: shown only when N PRs bounced today (label `automerge failed`).

The dropdown lists the queue (`▶` marks the PR the lander is on now, label
`autolanding`), the PRs that failed today, and your open PRs not yet in the
queue. A click on a PR opens it. Two links open
[github.com/pulls](https://github.com/pulls) and
[github.com/pulls/authored](https://github.com/pulls/authored).

No Dock icon (`LSUIElement`), no Xcode project: a Swift Package Manager
executable wrapped in a minimal `.app` bundle.

## How it counts

One `gh api graphql` call per refresh runs five GitHub searches, all scoped
to `org:<org>`. "Today" starts at local midnight, sent with its UTC offset.

| Number | Search |
|---|---|
| Tagged | `is:pr is:open label:"ready to review"` |
| Landed today | `is:pr is:merged label:autolanded merged:>=<midnight>` |
| Failed today | `is:pr is:open label:"automerge failed" updated:>=<midnight>` |
| My open | `is:pr is:open author:@me` |
| My merged today | `is:pr is:merged author:@me merged:>=<midnight>` |

GitHub search cannot filter on the time a label was added, so "failed today"
means an open, bounced PR that changed today. Counts come from GitHub's
`issueCount`; each list shows at most 50 PRs and then `… and N more`.

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
