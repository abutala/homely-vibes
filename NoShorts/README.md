# NoShorts

Gotchas, incidents and error reference: [Logbook.md](Logbook.md).

An iOS app that wraps YouTube in a `WKWebView`, blocks all Shorts content (navigation, feed shelves, autoplay), and lands on **Playlists** (`/feed/playlists`) instead of the algorithmic home page.

Architecture and V2 rationale live in [V2_PRD.md](V2_PRD.md).

## Features

- **Shorts blocking**: removes Shorts tab, home feed shelf, and all `/shorts/` links from the DOM.
- **Playlists as default landing**: app launches into `/feed/playlists`. Any navigation to `/` (algorithmic home) — YouTube's in-page Home tab, the logo, the toolbar Home button, post-login redirects — is caught and rewritten via KVO on `webView.url` (SPA `pushState`) plus `WKNavigationDelegate` (full-page navs). The `/` intercept skips forward/back navs so the toolbar chevrons don't appear broken.
- **Auto-rotate to landscape on video play**: JS reports `<video>` `play`/`pause`/`ended` events; a 400ms debounce coalesces buffering-driven pause↔play blips before flipping orientation. Portrait when not playing.
- **Fullscreen on play**: a fresh video start (content or ad, `currentTime < 1s`) calls the element's native `webkitEnterFullscreen()`, with a retry on `playing` if media wasn't loaded yet. Resume-from-pause does *not* re-enter — a manual fullscreen exit isn't fought. Fullscreen exits automatically when the video ends. See the fullscreen entry in [Logbook.md](Logbook.md) for why it's done exactly this way.
- **Autoplay gated natively**: `mediaTypesRequiringUserActionForPlayback = .video`. The former JS `video.play()` wrapper was removed 2026-07-09 — prototype tampering tripped YouTube's stream attestation and killed playback (see [V2_REMEDIATION_PLAN.md](V2_REMEDIATION_PLAN.md) §3a).
- **Shorts navigation guard**: full-page navigations to `/shorts` are cancelled in `WKNavigationDelegate`; SPA (`pushState`) navigations are caught Swift-side by the KVO observer on `webView.url`, which bounces back (`goBack()`, else Playlists). The old JS `pushState` wrapper is gone for good — page-JS tampering trips attestation ([#6](https://github.com/abutala/homely-vibes/issues/6) P1).
- **Session timer**: 30-minute countdown badge (top-right); turns orange at 5min, red at 1min, exits at 0.
- **Top toolbar**: 4 destination shortcuts — Playlists, Liked Videos, All Subscriptions, Account/Login.
- **Bottom toolbar**: back, forward, search (expands inline), home, reload. Back/forward mirror `WKWebView.canGoBack`/`canGoForward` via KVO — refreshed live rather than only at `didFinish` so the chevrons stay accurate through cancelled navs.
- **Google sign-in**: works natively in-app (no Safari handoff required).
- **DNS bypass, per-app + per-domain**: a `LocalProxy` (loopback-only `NWListener`) resolves `*.youtube.com` via DoH to `dns.google` and tunnels bytes to the resolved IP. The proxy is set on `WKWebsiteDataStore.default().proxyConfigurations` with `matchDomains = ["youtube.com"]`, so **only** `*.youtube.com` traffic goes through it. Everything else (`googlevideo`, `ytimg`, `doubleclick`, `googleapis`) resolves directly through system DNS. This is what lets NoShorts reach YouTube on a phone where NextDNS pinholes `*.youtube.com` for every other app — the bypass is scoped to this WKWebView data store and doesn't leak to Safari.

## Requirements

- macOS with Xcode 16+
- iOS 18+ device or simulator
- Apple ID (free tier sufficient for personal sideloading)

## Setup

1. **Install Xcode 16+** from the App Store and sign Xcode into your Apple ID (Xcode → Settings → Accounts). The Apple ID login is what lets Xcode auto-download the on-device Developer Disk Image (DDI) — without it, device deploys fail with "Developer disk image could not be mounted".
2. **Enable Developer Mode on the iPhone**: Settings → Privacy & Security → Developer Mode → On → reboot → confirm. Required on iOS 16+ before any unsigned/dev build will mount.
3. Open `NoShorts.xcodeproj` in Xcode.
4. Select your team under **Signing & Capabilities** → your Apple ID. Xcode rewrites `DEVELOPMENT_TEAM` in `project.pbxproj` automatically — verify with `grep DEVELOPMENT_TEAM NoShorts.xcodeproj/project.pbxproj` and commit the change.
5. Connect your iPhone, select it as the run destination.
6. **Cmd+R** to build and install.

## Building an IPA (for Sideloadly)

Use this when you want to install on a device without attaching Xcode, via [Sideloadly](https://sideloadly.io). Sideloadly re-signs at install time, so the IPA we ship is **unsigned** — no Apple ID, team, or provisioning profile setup is required on the building Mac.

### 1. Build the IPA

From the repo root:

```bash
NoShorts/scripts/build_ipa.sh 2>&1 | tee /tmp/noshorts-build-ipa.log
```

Output: `build/NoShorts.ipa` (≈135 KB). The script runs `xcodebuild` with code-signing disabled, packages `NoShorts.app` into `Payload/`, zips it, and prints the final path.

If you previously built signed in Xcode, the script still works — it uses a separate `build/sideload/` derived-data path so it won't conflict with Xcode's own DerivedData.

### 2. Install via Sideloadly

#### Windows: iTunes requirement
Sideloadly needs iTunes for Apple device drivers — **do not use the Microsoft Store version**. Download the direct installer from Apple's website (`apple.com/itunes`). You do not need to be logged into iTunes; your Apple ID is entered in Sideloadly directly. iTunes does not need to run in the background after setup.

#### Initial install (USB)
1. Download and open [Sideloadly](https://sideloadly.io) (free, Mac/Windows)
2. Connect your iPhone via USB
3. Drag `NoShorts.ipa` onto the Sideloadly window
4. Enter your Apple ID — Sideloadly re-signs the app with your free developer certificate
5. Click **Start** and wait for **"Done"** in the status bar
6. On the iPhone: **Settings → General → VPN & Device Management → [your Apple ID] → Trust**

#### Enable wireless re-signing (optional)
After the first USB install, you can cut the cable for future re-signs:

1. With iPhone still connected via USB, open iTunes
2. Click the iPhone icon (top-left) → **Summary** tab → **Options**
3. Check **"Sync with this iPhone over Wi-Fi"** → click **Sync**
4. Unplug — Sideloadly will now detect the device over Wi-Fi when both are on the same network

> If Sideloadly doesn't detect the device wirelessly, open iTunes and wake the iPhone screen.

#### Auto re-sign
Free Apple IDs must re-sign every 7 days. Leave the **Sideloadly daemon running in the system tray** — it re-signs automatically before expiry, wirelessly if Wi-Fi sync is enabled. To force a manual re-sign, drag the IPA in again and hit **Start**.

## How It Works

Three `WKUserScript` injections run on every page:

**`atDocumentStart` (`earlyScript`)**:
- Injects CSS to hide Shorts elements before first paint (`.pivot-shorts`, `ytm-shorts-lockup-view-model`, etc.)
- **CSS-only by design.** It previously also wrapped `HTMLVideoElement.prototype.play()`,
  `history.pushState`/`replaceState`, and hid `window.webkit` on `accounts.google.com`. All three were
  removed 2026-07-09: page-visible JS tampering is detectable by YouTube's BotGuard attestation, which
  responded by killing googlevideo media streams mid-body (`200 OK` + zero bytes, no `pot=` parameter,
  `playerfallback/1`). Removing them (plus the honest UA) restored playback on iOS 26.5.2.

**`atDocumentEnd` (`shortsBlockScript`)**:
- DOM removal of all Shorts-related elements
- Debounced `MutationObserver` (300ms) re-runs removal as YouTube's SPA loads new content

**`atDocumentEnd` (`videoEventScript`)**:
- Passive `play`/`pause`/`ended` listeners post video lifecycle to Swift (drives the orientation lock)
- On fresh play, enters native fullscreen via `webkitEnterFullscreen()` (retry on `playing`); exits on `ended`
- Listener-only — calls standard APIs, never touches prototypes (see the attestation gotcha above)

`WKNavigationDelegate` intercepts full-page navigations to `/shorts` and to `/` (or empty path) on `*.youtube.com`, redirecting both to the All Subscriptions grid.

A `KVO` observer on `webView.url` catches SPA URL changes (`history.pushState`/`replaceState` from YouTube's own routing) — `decidePolicyFor` does NOT fire for SPA navigations, so KVO is the catch-all. When the URL becomes `/shorts…`, the observer bounces back (`goBack()` if possible, else Playlists). When the URL becomes `/`, it forces a real navigation to Playlists; rewriting the URL alone wouldn't stop YouTube's home content from being rendered.

## Block-YouTube-in-Chrome Setup (DNS bypass)

The goal: YouTube blocked in Chrome (and Safari, and every other browser on the device), but still accessible inside this app.

Why this is hard on iOS, why DoH slips past NextDNS, and what the bypass does and doesn't defend against: [Logbook.md](Logbook.md).

### How this app works around it
1. **System level**: install [NextDNS](https://nextdns.io) as a **DNS profile** and add `youtube.com` (+ subdomains) to the deny list. This blocks YouTube in Chrome, Safari, and any other browser. Full setup steps below.
2. **App level**: this app runs an **in-process HTTP CONNECT proxy** on `127.0.0.1`. The proxy resolves hostnames via **DoH** (`https://dns.google/dns-query`) instead of system DNS, so it returns YouTube's real IP regardless of NextDNS filtering.
3. **WKWebView wiring**: `WKWebsiteDataStore.proxyConfigurations` (iOS 17+) points the web view at the local proxy. All TLS traffic is tunneled through it.

### NextDNS setup (full instructions)

**1. Create a NextDNS account**
- Go to [nextdns.io](https://nextdns.io) and sign up (free tier is sufficient — 300K queries/month per profile)
- A new "config" is created automatically with a random ID like `abc123`

**2. Configure the denylist**
- In the NextDNS dashboard, open your config → **Denylist** tab
- Add each of these entries (one per line):
  - `youtube.com`
  - `www.youtube.com`
  - `m.youtube.com`
  - `youtu.be`
  - `youtubei.googleapis.com` (optional — blocks the YouTube app's API; only add if you want to also kill the native YouTube app)
- NextDNS does **not** auto-block subdomains, so list the variants explicitly. Wildcards aren't supported in the basic denylist.

**3. Install the NextDNS profile on iOS**

Two options — pick one.

*Option A: NextDNS iOS app (easiest)*
- Install **NextDNS** from the App Store
- Open the app, sign in with your NextDNS account (or paste your config ID)
- Tap the big toggle to enable. iOS will prompt to install a DNS profile — tap **Allow**, then go to Settings and confirm install (Face ID / passcode)
- Verify in Settings → General → **VPN & Device Management** → **DNS** — NextDNS should show as the active DNS profile

*Option B: Configuration profile (no app)*
- In the NextDNS dashboard → **Setup** tab → **iOS** section → tap **Download Configuration Profile**
- Open the downloaded `.mobileconfig` on the iPhone, install via Settings prompt
- Same end result; doesn't install an app

**4. Verify NextDNS is active**
- Settings → General → VPN & Device Management → DNS → should list NextDNS (not "Automatic")
- Open Chrome/Safari → navigate to `youtube.com` → expect a "This site can't be reached" / DNS-failure error
- Open NextDNS dashboard → **Logs** tab → you should see blocked queries for `youtube.com`

**5. Verify the NoShorts app still works**
- Launch this app — it should load YouTube successfully despite the system-wide block
- If it doesn't, check Console.app (with iPhone connected) for `LocalProxy:` log lines:
  - `LocalProxy listening on 127.0.0.1:NNNNN` — proxy started successfully (port should be > 0)
  - `LocalProxy: incoming connection` — WKWebView reached the proxy
  - `LocalProxy: CONNECT www.youtube.com:443 -> <ip>` — DoH resolved the host

When any of that doesn't hold, see the NextDNS bypass entries in [Logbook.md](Logbook.md).

### Components
- [`DoHResolver.swift`](NoShorts/DoHResolver.swift) — minimal DNS-over-HTTPS client, raw DNS wire format over `URLSession`. Handles A records with TTL caching.
- [`LocalProxy.swift`](NoShorts/LocalProxy.swift) — `NWListener` HTTP CONNECT proxy. Parses `CONNECT host:port`, resolves via DoH, opens an `NWConnection` to the IP, tunnels bytes both ways.
- [`ContentView.swift`](NoShorts/ContentView.swift) — starts the proxy on `WebViewModel.init()` and assigns `WKWebsiteDataStore.default().proxyConfigurations = [ProxyConfiguration(httpCONNECTProxy:)]`.
