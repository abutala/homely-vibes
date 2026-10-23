# ClaudeUsageBar

Gotchas, incidents and error reference: [Logbook.md](Logbook.md).

A macOS menu bar app that shows your Claude Code plan usage — the same
5-hour session limit and 7-day (weekly) limit the `/usage` slash command
shows inside an interactive `claude` session — without opening a terminal.

Not sandboxed, no Dock icon (`LSUIElement`), no Xcode project — it's a plain
Swift Package Manager executable wrapped into a minimal `.app` bundle so it
can be launched from Finder/Spotlight/login items like a normal app.

## How it works

- **Auth**: reads the token the **Claude desktop app** keeps for itself — not
  the `claude` CLI's, which is a separate login. Each tick decrypts
  `oauth:tokenCacheV2` from the desktop app's `config.json` with the
  `Claude Safe Storage` Keychain secret, read once via `/usr/bin/security`.
  The first read shows one Keychain prompt; answer **Always Allow**. The app
  only reads: the desktop app refreshes its own tokens while it runs. Format
  and selection rules: "Desktop token cache" in [Logbook.md](Logbook.md).
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
- **UI**: `NSStatusItem` menu bar title (`58% 2.4h · 82% 3.1d`) — 5-hour window
  first, then 7-day. The title reports what is **left**, not what was consumed:
  budget remaining (`100 - utilization`) and time until reset, shown as the
  largest non-zero unit only, days and hours to one decimal (`3.1d` / `2.4h` /
  `47m`). Time is floored, so it
  understates rather than overstates what's left; resolution sharpens to
  minutes exactly as a window runs low. An absent `five_hour` window means
  nothing has been spent yet and renders `100% 5.0h`. The dropdown keeps the
  opposite convention — percent *consumed* plus a precise reset time: absolute
  wall-clock with a two-unit countdown (`resets 11:20 PM (in 1h 43m)`,
  weekday-prefixed when the reset falls on another day). The title stays terse
  because it competes for menu bar width; the dropdown is where there is room.
  The dropdown also adds usage-credit spend against its limit, a link to raise
  that limit, a manual refresh, a refresh-interval picker, and a quit item.
- **Pace icons**: each window carries an icon when its spend needs attention —
  tight after its section in the title (`10% 2.5h⚠︎ · 0% 3.0d!`), and at the
  end of the dropdown row.
  Red `!` means the window is spent (100% or more used). Yellow `⚠︎` means the rest of the
  window needs a cut of more than 25% below even spend (100% over the whole
  window): it fires when `left% < 75 × timeLeft / windowLength`. The alarm
  tightens as the window ends — with 90% of the window left it fires above
  32.5% used, with 10% left above 92.5%. The rule runs on the displayed
  (rounded) percent, and a window past its reset gets no icon. Logic and table:
  `PaceAlert.swift`. `⚠︎` means pace only; a failed refresh uses `↻` (below).
- **Forecast**: under each dropdown row, an indented line projects the window
  at its average rate so far — `At this pace: 80% at reset`, or, when 100%
  lands before the reset, only when it runs out:
  `At this pace: runs out Sun 4:20 AM (in 1d 13h)`. The first 5% of a window
  shows `Too early to project`; a spent window shows `Spent until reset`.
  Logic: `Forecast.swift`.
- **Dropdown contrast**: info rows stay enabled (`autoenablesItems = false`) so
  they render at full contrast; AppKit greys out disabled rows. A click on one
  only closes the menu.
- **Failure states**: a failed refresh never blanks a working display — the last
  good numbers stay, marked with a trailing `↻`, with the reason in the dropdown. "Open the
  Claude app and sign in" appears only when the desktop login is genuinely
  absent, signed out or expired; a *blocked* Keychain read says so instead and
  notes that it is retrying, because telling you to sign in when you already
  are is a dead end.
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
.build/debug/ClaudeUsageBar --probe-token   # reads the desktop app's token step by step; never prints a secret
.build/debug/ClaudeUsageBar --probe-usage   # one-shot fetch + print, no menu bar UI
CLAUDE_USAGE_DEBUG=1 .build/debug/ClaudeUsageBar --probe-usage  # also dumps the raw response body to stderr
```

The running app also logs every poll tick (success/failure/reason) and sleep/wake
events to the unified log, subsystem `com.deviationlabs.ClaudeUsageBar`,
category `refresh`:

```bash
log show --predicate 'subsystem == "com.deviationlabs.ClaudeUsageBar"' --last 3d 2>&1 | tee /tmp/claudeusagebar-log.log
log stream --predicate 'subsystem == "com.deviationlabs.ClaudeUsageBar"'   # live
```
