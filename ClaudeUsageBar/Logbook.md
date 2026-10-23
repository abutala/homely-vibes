# ClaudeUsageBar — Logbook

Learnings and landmines. How to use this module: [README.md](README.md).

---

## Incidents

### 2026-10 — CLI signed out; token source moved to the desktop app

The bar showed `⚠︎` stale numbers for over a day. The unified log had
`FAILED reason=credentials expired` on every tick and `still failing after CLI
nudge` every 12 minutes. The real state: `claude auth status` said
`"loggedIn": false`. The CLI had rewritten its `Claude Code-credentials` item
with `accessToken: ""`, `expiresAt: 0` and no `refreshToken`. The item still
parsed, so a sign-out read as an expiry and the nudge ran with nothing to
refresh. About 75 nudges also failed to refresh the token before the sign-out;
why is unconfirmed.

The CLI and the Claude desktop app are separate apps with separate logins. The
desktop app stayed signed in throughout. On a Mac where the CLI routes through
Fireworks (`ANTHROPIC_BASE_URL`), the CLI has no reason to keep a claude.ai
login at all. So the bar now reads **only the desktop app's token** (see
"Desktop token cache" below), and the CLI read, the app's own Keychain item and
the `claude auth status` nudge are gone.

Builds before this change left an item `com.deviationlabs.ClaudeUsageBar` in
the login keychain holding a stale CLI token. Nothing reads it any more; delete
it with `security delete-generic-password -s com.deviationlabs.ClaudeUsageBar`.

### 2026-08 — Menu bar stuck on `credentials expired`

The unified-log tick logging (the `log show` / `log stream` commands under
Diagnostics in [README.md](README.md)) was added after a 2026-08 incident
(`homely-vibes-archived#250`) where the bar stayed stuck on `credentials expired`
for 60+ hours. The poll timer was firing every 180s and correctly reporting an
expired upstream token; it recovered when a `claude` session rotated it. If a
stall recurs, compare `gapSinceLastTick` and any `willSleep`/`didWake` pair
around it to tell App Nap throttling apart from a real, repeated failure.

---

## Landmines

### Desktop token cache

The desktop app keeps its OAuth tokens in
`~/Library/Application Support/Claude/config.json`, key `oauth:tokenCacheV2`:
base64 of an Electron `safeStorage` blob. Decryption is Chromium OSCrypt on
macOS: strip the `v10` prefix, derive a 16-byte key with PBKDF2-HMAC-SHA1 over
the `Claude Safe Storage` Keychain secret (salt `saltysalt`, 1003 rounds), then
AES-128-CBC with an IV of 16 spaces and PKCS7 padding. Prior art: the
`ai-usagebar` crate.

The plaintext is a JSON object with one entry per (OAuth client, scope set):

```
"acct:<account>|<client>:<org>:https://api.anthropic.com:<scopes>":
  { token, refreshToken, expiresAt (ms), subscriptionType, rateLimitTier, … }
```

Every entry seen (four, 2026-10) returned HTTP 200 from `/api/oauth/usage`,
including one scoped only `user:profile`. `selectToken` takes entries for
`lastKnownAccountUuid` on the Anthropic API base, drops expired ones and keeps
the one that lasts longest. A blank `token` is skipped.

The format is undocumented. A desktop update can move it; the dropdown then
says `credentials unreadable`. `oauth:tokenCache` (no `V2`) is an older copy and
is not read.

### Keychain access

macOS gates a Keychain read through **two** independent lists: the item's ACL
application list *and* its **partition list**. Both must admit the caller.

The `Claude Safe Storage` secret is read only through `/usr/bin/security`, so
the "Always Allow" grant belongs to that tool, not to this app: rebuilds and
ad-hoc debug binaries do not re-prompt. The desktop app creates that item once
and never rewrites it, so the grant lasts. The secret stays in memory for the
life of the process and is dropped if a decrypt fails.

The CLI's item was the opposite case: the CLI rewrites it on every token
rotation (`mdat` moves, `cdat` stays put) and each rewrite resets both lists,
so no grant against it could last. `cdat` vs `mdat` is the quick way to tell
whether some other process rewrites an item.

Only a query that returns the secret prompts. An attributes-only query
(`security find-generic-password -s <service>` without `-w`) is silent.

### Code signing

`build_app.sh` signs the bundle with the first **Apple Development** identity,
else a self-signed certificate named `ClaudeUsageBar Self-Signed` (override with
`CLAUDE_USAGE_BAR_SIGN_IDENTITY`), else ad-hoc with a warning. Since the token
moved to the desktop app, signing no longer affects Keychain prompts (see
above). Verify with `codesign -d -r- ClaudeUsageBar.app`.

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

Test each numeric arm directly (`DesktopTokenReaderTests`), not through the
stderr fallback — a dead arm hides behind a test that only proves the fallback.

### The usage endpoint is undocumented

`GET https://api.anthropic.com/api/oauth/usage` was reverse-engineered from the
installed `claude` binary via `strings`; it is not publicly documented, so the
schema can move without notice — a payload that no longer parses surfaces as
`unexpected response` in the dropdown
(`Unavailable (…)` on a cold start, `Stale data (…)` after a good fetch). The response also carries further
fields (per-channel overage, codenamed feature flags) not surfaced yet.

### `utilization` above 100 is unconfirmed

`!` fires at 100% used, not only above it. No captured response, doc or bug
report shows `utilization` above 100 (TRIAL, 2026-10-23), so a strict `> 100`
might never fire. If a capture (`CLAUDE_USAGE_DEBUG=1 … --probe-usage`) ever
shows a value above 100, the title clamps percent left at `0%` with the `!`.

### Known limitations

- This app never runs the OAuth refresh itself, and must not. Anthropic
  **rotates the refresh token on use**, so spending it here would leave the
  desktop app holding a dead one, i.e. sign it out. The desktop app refreshes
  its own tokens while it runs; if it stays closed past the last entry's
  `expiresAt`, the bar says `Claude desktop login expired` until it is opened.
- No auto-launch-at-login wiring yet — open the `.app` manually, or add it
  to System Settings → General → Login Items.
- No WidgetKit desktop widget — this is menu-bar only.

---

## Error reference

### The menu bar says "Claude: —"

Read the dropdown — it names the cause, and only some are fixed by opening the
desktop app:

| Dropdown says | Meaning | Fix |
|---|---|---|
| `Claude desktop app not found` | No `config.json`, or no `Claude Safe Storage` item | Install the Claude desktop app and sign in |
| `Claude desktop app is signed out` | No token for this account in the cache | Open the Claude app and sign in |
| `Claude desktop login expired` | Every cached token is past `expiresAt` | Open the Claude app; it refreshes on its own |
| `Keychain access denied` / `keychain locked` | The *read* of `Claude Safe Storage` was refused | Unlock the login keychain; answer the prompt with Always Allow |
| `credentials unreadable` | Decrypt or parse failed | The desktop's cache format likely moved; see "Desktop token cache" |

A working display is never blanked by a failed refresh: the last good numbers
stay with a `⚠︎` and the reason. So "Claude: —" means it has *never* succeeded
since launch. Check each step with `.build/debug/ClaudeUsageBar --probe-token`.
