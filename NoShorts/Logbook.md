# NoShorts — Logbook

Learnings and landmines. How to use this module: [README.md](README.md).

---

## Incidents

### 2026-07-09 — Fullscreen in WKWebView (why `webkitEnterFullscreen`, why the retry)

Established empirically via simulator probe, 2026-07-09:

- **The Element Fullscreen API does not exist in iOS WKWebView.** `document.fullscreenEnabled` is
  `undefined` (prefixed variant too) even with `WKPreferences.isElementFullscreenEnabled = true`.
  Any `requestFullscreen()`-based approach is dead code here.
- **Delegating to YouTube's own fullscreen button doesn't work.** The mweb button doesn't exist in
  the DOM until playback starts, and once it does, YouTube ignores synthetic clicks
  (`isTrusted: false`). Worse, a matched-but-ignored click can short-circuit fallbacks — don't.
- **`webkitEnterFullscreen()` throws `InvalidStateError` until media is loaded**, so a `play`-time
  call can be too early. Call it on `play` (fresh starts only) and retry on `playing`, when a
  renderable frame guarantees valid state.
- Native fullscreen is the **system video player** — the same fullscreen real iPhone Safari users
  get on m.youtube.com. Captions render as text tracks (CC button in the native controls), not
  YouTube's DOM overlay.

---

## Landmines

### Why mobile user agent?
YouTube's mobile site (`m.youtube.com`-style layout via user agent) renders more predictably in WKWebView than the desktop site. The app uses `applicationNameForUserAgent = "Version/26.5 Mobile/15E148 Safari/604.1"`, so WebKit generates a truthful UA (real OS + WebKit version) with a Safari-shaped suffix. **Do not pin a fake `customUserAgent`**: the old iOS-17 pin contradicted the real WebKit fingerprint and contributed to YouTube's attestation failures (V2_REMEDIATION_PLAN.md §3a).

### Why `@Observable` instead of `ObservableObject`?
Swift 6 strict concurrency prevents `@MainActor` classes from conforming to `ObservableObject`. Using `@Observable` macro with `@ObservationIgnored` on the `WKWebView` property sidesteps the issue cleanly.

### Why `atDocumentStart` for CSS injection?
Injecting CSS before paint prevents the Shorts shelf from flickering in before the DOM removal JS runs. Both scripts run together — CSS hides immediately, JS removes the nodes.

### Why debounced `MutationObserver` instead of `setInterval`?
`setInterval` at 800ms caused page freezes on YouTube's heavy SPA. A debounced (300ms) `MutationObserver` fires only when the DOM actually changes and doesn't block the main thread.

### Google sign-in in WKWebView
Google detects WKWebView via `window.webkit` and can block sign-in with a "browser not supported" error. The old workaround (removing `window.webkit` on `accounts.google.com`) was stripped with the 2026-07-09 attestation fix. Existing sessions persist in the default data store's cookie jar, so this only matters for *fresh* sign-ins — if one hits the block, revisit under [#6](https://github.com/abutala/homely-vibes/issues/6) (the hide was scoped to accounts.google.com and may be safe to restore alone; verify playback with Web Inspector after).

### Discovering actual mobile YouTube element names
YouTube's mobile DOM uses custom elements not documented anywhere (`ytm-shorts-lockup-view-model`, `ytm-pivot-bar-renderer`, etc.). To discover them, inject `document.querySelectorAll('*')` filtered to custom elements via `evaluateJavaScript` with a Swift completion handler — `console.log` output is not accessible from Swift.

### Xcode project settings
- `SDKROOT` must be `iphoneos`, not `auto` — `auto` resolves to macOS SDK and breaks `UIViewRepresentable`
- `SUPPORTED_PLATFORMS` must exclude `macosx` and `xros` for the same reason
- `DEVELOPMENT_TEAM` is rewritten by Xcode when you pick a team in Signing & Capabilities — don't hand-edit it. If you fork the project on a fresh account, expect a one-line diff in `project.pbxproj` to commit.

### Autoplay interception
Native-only: `mediaTypesRequiringUserActionForPlayback = .video`. The earlier claim that a JS-level `HTMLVideoElement.prototype.play()` override was "the reliable fix" dated from the broken-proxy era and is disproven — the wrapper itself was tripping stream attestation. If autoplay leaks through the native gate, solve it Swift-side ([#6](https://github.com/abutala/homely-vibes/issues/6)), never by re-tampering with the prototype.

### Why blocking YouTube per-app is hard on iOS
- Chrome on iOS has no extensions and no per-site content blocking
- Screen Time's "Never Allow" list requires "Limit Adult Websites" enabled, which has collateral damage
- DNS-level blocking (NextDNS, Pi-hole, etc.) is system-wide — it affects WKWebView too, since WKWebView runs in a separate process and uses system DNS
- iOS has no per-app DNS routing on a free developer account (`NEAppProxyProvider` requires paid entitlements)

### Why DoH bypasses NextDNS
NextDNS as a DNS profile reroutes the system DNS resolver. But it does **not** intercept arbitrary HTTPS traffic. A POST to `https://dns.google/dns-query` is just regular HTTPS — the request body happens to contain a DNS wire-format query. NextDNS sees an HTTPS connection to `dns.google`, not a DNS query, so it doesn't filter the response.

### Threat model (what this does and doesn't defend against)
- ✅ Defends against: typing `youtube.com` in Chrome, clicking a YouTube link in any other app, tapping the YouTube app's web bridge
- ❌ Does not defend against: someone with the device disabling NextDNS in Settings, or installing a different browser, or using cellular data with the NextDNS profile only configured for Wi-Fi
- This is a self-control tool, not a hardened parental control. Determined bypass is trivial. The friction is the point.

### Why not Network Extension / `NEAppProxyProvider`?
Per-app VPN via `NEAppProxyProvider` would be the textbook iOS solution. It requires `com.apple.developer.networking.networkextension` with `app-proxy-provider`, which is gated behind a **paid** Apple Developer account ($99/yr). The DoH-proxy-in-app approach achieves the same outcome on a free account.

### Why DoH (DNS wire format), not DoH (JSON)?
Google's DoH endpoint accepts both `application/dns-message` (RFC 1035 wire format) and `application/dns-json`. Wire format is ~50 bytes vs JSON's ~500 bytes per query, and avoids JSON parsing of arbitrary RDATA.

### Why HTTP CONNECT, not full HTTP proxy?
WKWebView using `proxyConfigurations` sends `CONNECT host:443` for HTTPS targets and tunnels TLS verbatim afterward. Since YouTube is HTTPS-only, supporting only CONNECT is sufficient. Plain HTTP requests (which would arrive without CONNECT) get a `405 Method Not Allowed`.

---

## Error reference

### Troubleshooting device deploys

- **"Developer disk image could not be mounted on this device"** — Xcode can't mount the on-device debug bridge. Causes, in likelihood order:
  1. Developer Mode is off on the iPhone (Settings → Privacy & Security → Developer Mode → On → reboot)
  2. Xcode is not signed into your Apple ID (Xcode → Settings → Accounts) — without it, the matching DDI can't auto-download
  3. The device's iOS minor version is newer than any DDI Xcode has — open Xcode → Window → Devices and Simulators, select the iPhone, click **Get** to fetch the matching DDI. If unavailable, update Xcode.
  4. Mac ↔ iPhone trust didn't carry over (e.g., fresh macOS user account) — Settings → General → Transfer or Reset iPhone → Reset → Reset Location & Privacy, then replug and tap **Trust**.
- **App installs but crashes immediately with `dyld_shared_cache_extract_dylibs` error** — different problem from the above; happens when the device's iOS is newer than Xcode's symbol cache. Edit Scheme → Run → Info → uncheck **Debug executable**.

### NextDNS bypass troubleshooting

- **YouTube loads in Chrome too**: NextDNS not active, or denylist not saved. Re-check the "Verify NextDNS is active" step in [README.md](README.md).
- **App shows blank page**: proxy didn't bind (check logs for port 0 or `listener failed`); reinstall app.
- **App loads YouTube but Chrome also loads it**: device might be on cellular with no NextDNS rules for cellular profile — set up the same NextDNS config for cellular in NextDNS dashboard → **Settings** → **iOS** → enable for both Wi-Fi and cellular.

---

## References

- The iOS 26.5.2 playback outage, its diagnosis (Google stream attestation, not an OS network
  block), and the fix: [V2_REMEDIATION_PLAN.md](V2_REMEDIATION_PLAN.md).
- Architecture and V2 rationale: [V2_PRD.md](V2_PRD.md).
- Open follow-ups tracked at [#6](https://github.com/abutala/homely-vibes/issues/6).
