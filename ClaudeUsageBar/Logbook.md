# ClaudeUsageBar — Logbook

Learnings and landmines. How to use this module: [README.md](README.md).

---

## Incidents

### 2026-08 — Menu bar stuck on `credentials expired`

The unified-log tick logging (the `log show` / `log stream` commands under
Diagnostics in [README.md](README.md)) was added after a 2026-08 incident
(`homely-vibes-archived#250`) where the menu bar stayed stuck on
`credentials expired` for 60+ hours despite the underlying CLI token being valid
again — a restart fixed it, but the root cause (leading suspect: macOS App Nap
throttling the repeating `Timer` on a long-lived, no-window accessory app) was
never confirmed. If it recurs, `log show` now has the tick-by-tick history —
specifically the gap between ticks (`gapSinceLastTick`) and whether a
`willSleep`/`didWake` pair brackets the stall — to tell App Nap apart from a
genuine, repeated backend/keychain failure. See the issue for the fix candidates
once diagnosed.

### 2026-08 — Expired tokens

The CLI's access token lives **8 hours** and is refreshed only when `claude`
actually runs. Any longer gap — overnight, a quiet weekend — leaves the token
expired, and the widget has nothing valid to call the API with. Diagnosed from
the unified log in
`homely-vibes-archived#250` (closed; private archive): the poll
timer was firing perfectly every 180s and correctly reporting an expired
upstream token for ~25 hours, then recovered on its own the moment a `claude`
session rotated it. No restart was ever the fix.

Since we cannot refresh (rotation would log the CLI out — see "Known
limitations"), the app asks **the CLI** to do it: on an expired token it spawns

```
claude auth status
```

which is non-interactive, prints no secrets, returns in ~0.2s, and whose
refresh path is expiry-driven (`if (!force && !isExpired(expiresAt)) return
"not_needed"`). The CLI performs the refresh under its own `oauth_refresh_lock`,
serialised against its other sessions rather than racing them, and writes its
own Keychain item — we never do.

Deliberate constraints:

- **Only `.expired` triggers a nudge.** `.notFound` means there is nothing to
  refresh; `.accessDenied` means the read was blocked. Spawning the CLI helps
  neither.
- **Throttled to one attempt per 10 minutes.** An expired token stays expired
  until the CLI refreshes it, so an unthrottled nudge would fork a 256MB binary
  on every 180s poll for the whole window.
- **Resolved by absolute path.** A GUI app inherits a minimal `PATH`
  (`/usr/bin:/bin:/usr/sbin:/sbin`) with no Homebrew on it, so `claude` is
  found via an ordered candidate list, not by name. Check yours with
  `--probe-nudge`.

---

## Landmines

### Keychain access

macOS gates a Keychain read through **two** independent lists: the item's ACL
application list *and* its **partition list**. Both must admit the caller.

Earlier versions read the CLI's `Claude Code-credentials` item directly and
could never stop prompting, for compounding reasons:

1. Grants are recorded in the partition list against a `cdhash:` — which changes
   on every rebuild. (Signing with a certificate stabilises the *designated
   requirement*, which is the ACL half; it does nothing for the partition half.
   That distinction is what the previous version of this document missed.)
2. The `claude` CLI rewrites that item on every token rotation — its `mdat`
   advances while `cdat` stays put — and each rewrite resets both lists. So no
   grant could outlive a single token cycle.

The fix is to stop borrowing someone else's item. Every clean item in a login
keychain belongs to its reader:

| Item | Partition list | ACL entries |
|---|---|---|
| `Chrome Safe Storage` | `teamid:EQHXZ8M8AV` | 1 |
| `Slack Safe Storage` | `teamid:BQR82RBBHL` | 1 |
| `com.deviationlabs.ClaudeUsageBar` | `teamid:656D6H7G24` | 1 |

Because the app creates the item, macOS puts its **team ID** — stable across
every rebuild — in the partition list, and nothing else ever rewrites it. The
CLI's item is still the source of truth for the token, but it is only ever read
through `/usr/bin/security`, which carries `apple-tool:` in the partition list
of every one of these items and survives each rotation.

The hash-suffixed siblings `Claude Code-credentials-<hash>` are per-workspace
MCP OAuth caches (`{"mcpOAuth": …}`) with no `accessToken` at any level, and
are never consulted.

Verify the shape with:

```bash
security dump-keychain -a 2>/dev/null | grep -A12 com.deviationlabs.ClaudeUsageBar | tee /tmp/claudeusagebar-keychain.log
```

You want `teamid:` and **not** `cdhash:` in the partition list. A `cdhash:` there
means the item was created by an ad-hoc-signed build (see below) and will
re-prompt after the next rebuild; delete it with
`security delete-generic-password -s com.deviationlabs.ClaudeUsageBar` and
re-bootstrap from a signed build.

### Code signing

`build_app.sh` signs the bundle. This is not about Gatekeeper — an ad-hoc
signature has no certificate and therefore no team ID, so an item created by
such a build gets a `cdhash:` partition entry and the prompt comes back on every
rebuild. A certificate gives both a stable designated requirement:

```
designated => identifier "com.deviationlabs.ClaudeUsageBar"
  and anchor apple generic
  and certificate leaf[subject.CN] = "Apple Development: ..."
```

and a stable `teamid:` partition entry. Verify with
`codesign -d -r- ClaudeUsageBar.app`.

Note that `swift build` alone produces an ad-hoc binary, so the debug executable
and the signed `.app` do not share a grant. Develop with `--probe-keychain`;
trust the `.app` for the durable behaviour.

The script picks the first **Apple Development** identity in your keychain. With
no Apple Developer account, create a self-signed certificate once — Keychain
Access → *Certificate Assistant* → *Create a Certificate…*, name it
`ClaudeUsageBar Self-Signed`, type *Code Signing*, then re-run the script.
Override the name with `CLAUDE_USAGE_BAR_SIGN_IDENTITY`. With neither, the build
still succeeds but warns and falls back to ad-hoc.

Changing the signing identity invalidates existing grants, so expect one more
consent prompt after the first signed build.

### Debugging the original prompt loop

Facts worth keeping, because they are not obvious and cost real time:

- **A Keychain read is gated by two lists, not one.** The ACL application list
  *and* the partition list. Fixing only the designated requirement (the ACL
  half) leaves a `cdhash:` pinned in the partition half, and the prompt keeps
  returning. `codesign -d -r-` tells you nothing about the partition list —
  only `security dump-keychain -a` does.
- **`cdat` vs `mdat` on an item tells you who is rewriting it.** On
  `Claude Code-credentials`, `cdat` sits at the day you first signed in while
  `mdat` tracks the present: the CLI rewrites it on every token rotation, and
  each rewrite resets both access lists. That is why no grant against *that*
  item could ever be durable, and why this app owns its own instead.
- **Only a query that returns the secret prompts.** `kSecReturnData` triggers the
  consent dialog; an attributes-only query (`kSecReturnAttributes`) is silent, so
  use it to check whether an item exists without prompting.

### `security` CLI exit codes are not `OSStatus`

`/usr/bin/security find-generic-password … -w` exits with its own small curated
codes, not the raw `OSStatus` and not its low byte — item-not-found exits **44**.
A Unix exit status is 0–255, so a `case` on an `errSec*` constant (25293, 25308)
can never match. `classifySecurityFailure` maps `44` → not found and `51` → access
denied, then classifies by stderr: `could not be found` → not found;
`interaction` / `denied` / `cancel` / `authoriz` → access denied. Only the
not-found code is cheap to reproduce:

```bash
security find-generic-password -s <missing-service> -w; echo "exit=$?"
```

Test each numeric arm directly (`KeychainTokenReaderTests`), not through the
stderr fallback — a dead arm hides behind a test that only proves the fallback.

### The usage endpoint is undocumented

`GET https://api.anthropic.com/api/oauth/usage` was reverse-engineered from the
installed `claude` binary via `strings`; it is not publicly documented, so the
schema can move without notice — a payload that no longer parses surfaces as
`credentials unreadable` in the dropdown. The response also carries further
fields (per-channel overage, upgrade paths) not surfaced yet.

### Known limitations (v1)

- This app does not run the OAuth refresh itself, and must not. Anthropic
  **rotates the refresh token on use** — confirmed by decompiling the `claude`
  binary: the refresh response carries a new `refreshToken` *and* a
  `refreshTokenExpiresAt`, and the CLI's write-back aborts if the stored token
  changed underneath it (`if (y && y !== c) …`), a guard that only makes sense
  when the old token dies on use. Spending that single-use token here would
  leave the CLI holding a dead one, i.e. log you out. Instead the app *nudges*
  the CLI — see "Expired tokens" above.
- No auto-launch-at-login wiring yet — open the `.app` manually, or add it
  to System Settings → General → Login Items.
- The signing identity is resolved at build time from whatever is in your
  keychain, so a bundle built on one machine won't carry another's grant.
- No WidgetKit desktop widget — this is menu-bar only.

---

## Error reference

### The menu bar says "Claude: —"

Read the dropdown — it now names the cause, and only one of them is fixed by
signing in:

| Dropdown says | Meaning | Fix |
|---|---|---|
| `no Claude Code credentials on this Mac` | No `Claude Code-credentials` item exists | Run `claude` once |
| `credentials expired` | The CLI's token is past `expiresAt` | Usually self-healing — the app nudges the CLI to refresh (see "Expired tokens"). Persists only if the nudge cannot find or drive `claude`; check `--probe-nudge` |
| `Keychain access denied` / `keychain locked` | The token exists and is fine; the *read* was refused | Unlock the login keychain; see below |
| `credentials unreadable` | Payload did not parse | File a bug — the CLI's schema likely moved |

A working display is never blanked by a failed refresh: the last good numbers
stay with a `⚠︎` and the reason. So "Claude: —" means it has *never* succeeded
since launch.

### The Keychain prompt came back

It should not. If it does, find out which build created our item:

```bash
security dump-keychain -a 2>/dev/null | grep -A12 com.deviationlabs.ClaudeUsageBar | tee /tmp/claudeusagebar-keychain.log
```

- `partition: teamid:656D6H7G24` — correct, stable across rebuilds.
- `partition: cdhash:…` — the item was created by an **ad-hoc** build (plain
  `swift build`, no certificate, therefore no team ID). It will re-prompt after
  every rebuild. Repair:

  ```bash
  security delete-generic-password -s com.deviationlabs.ClaudeUsageBar
  ./Scripts/build_app.sh && open ClaudeUsageBar.app   # re-bootstrap from the signed app
  ```
