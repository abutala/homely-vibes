# ClaudeUsageBar

Gotchas, incidents and error reference: [Logbook.md](Logbook.md).

A macOS menu bar app that shows your Claude Code plan usage — the same
5-hour session limit and 7-day (weekly) limit the `/usage` slash command
shows inside an interactive `claude` session — without opening a terminal.

Not sandboxed, no Dock icon (`LSUIElement`), no Xcode project — it's a plain
Swift Package Manager executable wrapped into a minimal `.app` bundle so it
can be launched from Finder/Spotlight/login items like a normal app.

## How it works

- **Auth**: the app **owns its own Keychain item**, `com.deviationlabs.ClaudeUsageBar`,
  the way every well-behaved macOS app does (`Chrome Safe Storage`,
  `Slack Safe Storage`, …). Reads go, in order: in-memory cache → own item →
  bootstrap from the `claude` CLI's `Claude Code-credentials` item via
  `/usr/bin/security`, whose result is then written into our own item. A 401
  from the API drops *both* the memory cache and the own item, so the next tick
  re-bootstraps rather than replaying a token the server already rejected.
  See "Keychain access" in [Logbook.md](Logbook.md) for why this shape is the
  only durable one.
- **Data**: calls `GET https://api.anthropic.com/api/oauth/usage` with that
  bearer token — the same endpoint the CLI's `/usage` command calls. Response
  looks like:
  ```json
  {
    "five_hour": {"utilization": 77.0, "resets_at": "2026-08-14T04:49:59.72Z"},
    "seven_day": {"utilization": 27.0, "resets_at": "2026-08-18T04:59:59.72Z"},
    "seven_day_opus": null,
    "seven_day_sonnet": null
  }
  ```
  `utilization` is already a 0-100 percent, `resets_at` is ISO-8601.
  `seven_day_opus`/`seven_day_sonnet` are only populated on `max`/`team`
  plans. `spend.used`/`spend.limit` are minor-unit integers (cents) plus an
  `exponent`, so divide by `10^exponent` for dollars.
- **UI**: `NSStatusItem` menu bar title (`58% 2h · 82% 3d`) — 5-hour window
  first, then 7-day. The title reports what is **left**, not what was consumed:
  budget remaining (`100 - utilization`) and time until reset, shown as the
  largest non-zero unit only (`3d` / `2h` / `47m`). Time is floored, so it
  understates rather than overstates what's left; resolution sharpens to
  minutes exactly as a window runs low. An absent `five_hour` window means
  nothing has been spent yet and renders `100% 5h`. The dropdown keeps the
  opposite convention — percent *consumed* plus a precise reset time: absolute
  wall-clock with a two-unit countdown (`resets 11:20 PM (in 1h 43m)`,
  weekday-prefixed when the reset falls on another day). The title stays coarse
  because it competes for menu bar width; the dropdown is where there is room.
  The dropdown also adds usage-credit spend against its limit, a link to raise
  that limit, a manual refresh, a refresh-interval picker, and a quit item.
- **Failure states**: a failed refresh never blanks a working display — the last
  good numbers stay, marked `⚠︎`, with the reason in the dropdown. "Run `claude`
  once to sign in" appears only when the credentials are genuinely absent or
  expired; a *blocked* Keychain read says so instead and notes that it is
  retrying, because telling you to sign in when you already are is a dead end.
- **Refresh cadence**: 180s by default, changeable from the dropdown
  (30s / 1 / 3 / 5 / 10 / 30 min) and persisted in `UserDefaults`, so the
  choice survives relaunch. The default is deliberately slow: the 5-hour bar
  moves ~0.5%/min even at a heavy sustained pace and the 7-day bar far less,
  so polling faster mostly spends requests redrawing an unchanged number.

## Build & run

```bash
swift build                      # debug build, for development
.build/debug/ClaudeUsageBar      # run in foreground (Ctrl-C to quit)

./Scripts/build_app.sh           # release build wrapped as ClaudeUsageBar.app
open ClaudeUsageBar.app
```

## Diagnostics

```bash
.build/debug/ClaudeUsageBar --probe-keychain   # reports which source served the token (cache / own item / bootstrap); never prints a secret
.build/debug/ClaudeUsageBar --probe-usage      # one-shot fetch + print, no menu bar UI
.build/debug/ClaudeUsageBar --probe-nudge      # can the `claude` CLI be located and driven? shows each candidate path
CLAUDE_USAGE_DEBUG=1 .build/debug/ClaudeUsageBar --probe-usage  # also dumps the raw response body to stderr
```

`--probe-nudge` is safe to run at any time: on a still-valid token the CLI's
refresh short-circuits to "not_needed", so it only proves reachability.

The running app also logs every poll tick (success/failure/reason) and sleep/wake
events to the unified log, subsystem `com.deviationlabs.ClaudeUsageBar`,
category `refresh`:

```bash
log show --predicate 'subsystem == "com.deviationlabs.ClaudeUsageBar"' --last 3d 2>&1 | tee /tmp/claudeusagebar-log.log
log stream --predicate 'subsystem == "com.deviationlabs.ClaudeUsageBar"'   # live
```
