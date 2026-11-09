# Module notes

Part of the agent guide: [AGENTS.md](../AGENTS.md).

One block per module that has non-obvious setup. Usage lives in each module's `README.md`, incidents in its `Logbook.md`.

## August Module (`August/`)
- **Authentication**: Requires 2FA via phone/email, tokens cached for ~7 days
- **Main Features**: Smart lock monitoring, unlock duration alerts, door ajar detection, battery warnings, lock failure detection
- **Initial Setup**: Run `august_manager.py test` to trigger 2FA, then use `validate_2fa.py` with verification code
- **Key Classes**: AugustManager with state persistence for alert tracking
- **Alert Thresholds**: Configurable via CLI (default: 5min unlock, 10min ajar, 20% battery)

## AugustUnlock Module (`AugustUnlock/`)
- **Stack**: SwiftUI iOS app (NOT Python — no uv, no pytest). Same Xcode-project pattern as `NoShorts/` (`PBXFileSystemSynchronizedRootGroup`, sideload via `scripts/build_ipa.sh` + Sideloadly).
- **Purpose**: Every door on one screen, one below the other: a card that is the door's button, with a status circle and the door's text to its right. Opening the app sends nothing; the first tap on a door unlocks it, the next locks it. A Home Screen widget shows two door unlock buttons with Lock Both between them; a tap runs in the app's process in the background through the app's client (Bluetooth first), and only the sign-in line or a miss opens the app. The widget shares the `Shared/` files with the app and hands state through the Keychain (the app's access token, the per-door tap state). Near the door it talks to the lock over Bluetooth (a minimum Swift port of `yalexs-ble`) when the lock holds an offline key; otherwise it talks to August's cloud API directly (`api-production.august.com`). No home server or VPN in the loop; see the module README's "Why no server" and "Security notes" sections.
- **Key files**: `AugustClient.swift` (whole August REST client — login, email 2FA, token refresh, lock discovery, lock/unlock), `AugustBLEProtocol.swift` (Bluetooth frames, checksums, ciphers, key exchange; `swift test` covers it), `AugustBLEEngine.swift` (the Bluetooth path as a pure state machine) and `AugustBLELink.swift` (its CoreBluetooth adapter), `Shared/KeychainStore.swift` (on-device credential, offline-key and door-state storage), `ContentView.swift` (sign-in and the door list), `DoorRow.swift` and `DoorController.swift` (one door's row and command state), `AppDoorAction.swift` (a widget tap in the app's process), `AugustUnlockWidget/` (the widget extension: its lock-list client `WidgetCloud.swift`, the three toggles) and `Shared/DoorIntents.swift` (the taps' intents).
- **Install on the phone**: Sideloadly only — `open -a Sideloadly <ipa>`, check the phone is the selected device, press Start. Never Xcode or `devicectl install`: they use the plain bundle ID, so the phone gets a second copy with its own Keychain. Same for `NoShorts/`. A personal staging flow for the IPA may live in agent memory; check it before installing.
- **App vs widget**: change the widget without touching `AugustUnlock/AugustUnlock/`; a change to the app's files is its own PR, re-tested on the phone through open → tap → unlock → tap → lock on each door (see the module Logbook, 2026-10-30).
- **Gotchas**: `.invalidatableContent()` inside a widget button's label makes it inert under this install, and a toggle's hit area is only its body unless the body fills its half; two non-obvious August API details (a revoked API key; lock operations using a different key than login), plus two auth-flow bugs only a real device build surfaced (JSON booleans miscast as strings; a missing `"email:"` prefix on the session identifier) — see [AugustUnlock/Logbook.md](../AugustUnlock/Logbook.md) before touching API keys, endpoints, or the auth flow.

## BimpopAI Module (`BimpopAI/`)
- **Architecture**: FastAPI backend + Streamlit frontend
- **Features**: RAG system with document indexing, conversational AI
- **Optional Dependencies**: Uses streamlit extra (`uv sync --extra streamlit`)

## ClaudeUsageBar Module (`ClaudeUsageBar/`)
- **Stack**: Swift Package Manager executable wrapped into a `.app` bundle (NOT Python — no uv, no pytest). Menu bar widget (`LSUIElement`, no Dock icon) showing Claude Code plan usage.
- **Build**: `swift build` for dev; `./Scripts/build_app.sh` for the signed `.app`. `swift test` runs the XCTest target.
- **Token**: reads the **Claude desktop app's** token (`oauth:tokenCacheV2` in its `config.json`), decrypted with the `Claude Safe Storage` secret read via `/usr/bin/security`. Not the `claude` CLI's — a separate login, and on a Fireworks-routed Mac never a claude.ai one. Never refreshes. Detail: the module's Logbook.
- **Diagnostics**: `--probe-token` (each step of the token read), `--probe-usage` (one-shot fetch). Neither ever prints a secret.

## lib/ (shared library)
- **Config**: All modules source configuration from `lib/config.py` (OmegaConf-based hierarchical YAML)
- **Notifications**: Standardized via MyPushover, Mailer, MyTwilio classes
- **Secret I/O**: `lib/secure_io.py` — `write_secret_atomic(path, content)` for tokens we own (0o600 from birth), `ensure_secret_perms(path)` after third-party library writes (yalexs, SamsungTVWS). **All token/credential writes must go through these.**
- **File lock**: `lib/file_lock.py` — POSIX `fcntl.flock` context manager for cross-process serialization on shared resources (e.g. Ring token file used by RingSecurity + RingBeams). Yields its fd: a child given it via `pass_fds` keeps the lock after a killed parent.
- **TeslaPy Submodule**: External dependency managed as Git submodule

## formal Module (`formal/`)
- **Stack**: Quint models (Node tooling, NOT Python). `make formal-deps` then `make formal`; deliberately outside `setup`, `lint` and `test`, so the prod host never installs it.
- **Result semantics**: `make formal` (`quint run`) is a randomized search, so "holds" there is never "proved"; `make formal-verify` (Apalache) is exhaustive and needs JDK 21. See [formal/Logbook.md](../formal/Logbook.md) before trusting or extending a model.

## MergeQueueBar Module (`MergeQueueBar/`)
- **Stack**: Swift Package Manager executable wrapped into a `.app` bundle, same pattern as `ClaudeUsageBar/` (NOT Python). `swift test` runs the XCTest target; `./Scripts/build_app.sh --install` builds, copies to `/Applications` and relaunches.
- **Data**: one `gh api graphql` call per tick: queue searches over the pr-lander labels in one org, my-PR searches across every repo, and 7-day totals. `gh` is found by absolute path: a GUI app gets launchd's PATH, which lacks Homebrew.
- **Diagnostics**: `swift run MergeQueueBar --probe` prints one fetch.

## NodeCheck Module (`NodeCheck/`)
- **Purpose**: System node monitoring with continuous heartbeat tracking and automated device management
- **Testing**: Runs in isolation due to subprocess management patterns (uses pytest-forked)
- **Architecture**: Multi-process design requiring forked test execution to avoid state interference

## RachioFlume Module (`RachioFlume/`)
- **Integration**: Connects Rachio irrigation with Flume water monitoring
- **Architecture**: RachioClient, FlumeClient, WaterTrackingDB (SQLite), collector/reporter pattern
- **Usage**: `rfmanager.py` CLI with collect/status/report commands

## RingBeams Module (`RingBeams/`)
- **Purpose**: Daily battery, offline and tamper health check for Ring Beams motion sensors and Ring Alarm sensors via Node sidecar (ring-client-api over socket.io).
- **Sidecar**: `fetch_status.js` — exit-code contract documented at top of file (0/1/2/3/4/5). Python parent maps 3 and 5 to `BeamsAuthError`; other non-zero codes raise `RuntimeError` (so a Node module-load crash never gets misclassified as "auth required").
- **Token sharing**: reads/writes the same `config/tokens/ring_auth_token.json` as RingSecurity; a POSIX flock (`lib.file_lock`) serializes the two runs so overlapping refreshes don't produce `invalid_grant`.
- **Config dump**: `config_dump.py` writes a backup of every Ring device, changing no device setting, from REST and the sidecar's raw mode, under the same flock.

## RingSecurity Module (`RingSecurity/`)
- **Purpose**: Daily battery + offline health check for Ring cameras and doorbells via REST.
- **Authentication**: 2FA via `ring_manager.py auth`; token stored in `config/tokens/ring_auth_token.json`.
- **Token sharing**: see RingBeams — shared token, POSIX flock.
- **Settings helper**: `set_device_settings.py` changes one device's settings. It is a dry run unless given `--apply`, and it reports every field that moved.

## SamsungFrame Module (`SamsungFrame/`)
- **Authentication**: WebSocket token-based auth, saved to `config samsung_frame.token_file`
- **Main Features**: Image upload to Frame TV, matte/border management, slideshow control, art inventory management
- **Initial Setup**: The first command that connects triggers the TV pairing prompt, token auto-saved for future use
- **Key Classes**: SamsungFrameClient, TvIo (injected I/O), ImageUploadSummary
- **Monthly album**: `frame_album.py run` picks the next album from the photo-library queue and plays it; rules in the module README
- **CLI Commands**: `frame_run.py <folder>` runs the upload pipeline (ingest, dedup, upload, cleanup, slideshow); `manage_samsung.py` has status, list-art, list-mattes, download-thumbnails, update-mattes, cycle-images, start-slideshow, reboot, delete-all, purge
- **Image Requirements**: the pipeline converts HEIC/JPG/PNG originals to <=4K JPGs under `max_image_size_mb`; the client validates each file before upload

## ScreenShare Module (`ScreenShare/`)
- **Stack**: `build_app.py` fills an AppleScript template and compiles it with `osacompile`; `icon.py` draws the per-host icon with Pillow. Output is a launcher `.app` in `~/Applications` with a Dock tile, one per `screen_share.apps` entry.
- **Build**: `make screenshare-app` installs one app per `screen_share.apps` entry in config (`ScreenShareConfig` in `lib/config.py`). It reads Screen Sharing's `connectionsStore` and opens that entry's own URL, so it never adds a duplicate connection.
- **Runtime**: drives Screen Sharing through System Events, so the built app needs Accessibility permission, and loses it on each rebuild.

## Tesla Module (`Tesla/`)
- **Authentication**: Fleet API OAuth (previously TeslaPy — migrated in PR #178)
- **Main Features**: Powerwall monitoring, intelligent power management, battery history tracking, retry on transient Fleet API errors
- **Key Classes**: PowerwallManager, BatteryHistory, DecisionPoint, TeslaAPIClient

## VSCodeSidebarNotes Module (`VSCodeSidebarNotes/`)
- **Stack**: TypeScript VS Code / Cursor extension (NOT Python — does not use uv, pytest, or the rest of the repo's Python tooling).
- **Purpose**: Markdown sidebar that reads/writes `sidebar-notes.md` in the workspace root. Two-way sync with file watcher so Claude (or any external tool) can update the file and the sidebar refreshes live.
- **Build**: `cd VSCodeSidebarNotes && npm install && npm run compile` (esbuild → `dist/extension.js`). `npm run package-vsix` produces an installable `.vsix`.
- **Marketplace**: published under the `deviationlabs` publisher; see the module README for the publish flow.
- **Layout**: `package.json` (extension manifest), `src/` (TS source), `media/` (webview assets).
