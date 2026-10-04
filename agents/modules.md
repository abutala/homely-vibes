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
- **Purpose**: Open it and the door unlocks — no tap needed; tap the button again to lock. Talks to August's cloud API directly (`api-production.august.com`), no home server or VPN in the loop; see the module README's "Why no server" and "Security notes" sections.
- **Key files**: `AugustClient.swift` (whole August REST client — login, email 2FA, token refresh, lock discovery, lock/unlock), `KeychainStore.swift` (on-device credential storage), `ContentView.swift` (the whole UI, incl. the multi-lock picker).
- **Gotchas**: two non-obvious August API details (a revoked API key; lock operations using a different key than login), plus two auth-flow bugs only a real device build surfaced (JSON booleans miscast as strings; a missing `"email:"` prefix on the session identifier) — see [AugustUnlock/Logbook.md](../AugustUnlock/Logbook.md) before touching API keys, endpoints, or the auth flow.

## BimpopAI Module (`BimpopAI/`)
- **Architecture**: FastAPI backend + Streamlit frontend
- **Features**: RAG system with document indexing, conversational AI
- **Optional Dependencies**: Uses streamlit extra (`uv sync --extra streamlit`)

## ClaudeUsageBar Module (`ClaudeUsageBar/`)
- **Stack**: Swift Package Manager executable wrapped into a `.app` bundle (NOT Python — no uv, no pytest). Menu bar widget (`LSUIElement`, no Dock icon) showing Claude Code plan usage.
- **Build**: `swift build` for dev; `./Scripts/build_app.sh` for the signed `.app`. `swift test` runs the XCTest target.
- **Keychain**: owns its own item `com.deviationlabs.ClaudeUsageBar`; bootstraps from the `claude` CLI's item via `/usr/bin/security`. Never read the CLI's item with `SecItem` — see "macOS Keychain" in [practices.md](practices.md).
- **Signing matters for correctness, not Gatekeeper**: `swift build` is ad-hoc (no team ID) so items it creates are `cdhash`-pinned and re-prompt; only the certificate-signed `.app` gets a stable `teamid:` partition entry.
- **Diagnostics**: `--probe-keychain` (which source served the token), `--probe-usage` (one-shot fetch). Neither ever prints a secret.

## lib/ (shared library)
- **Config**: All modules source configuration from `lib/config.py` (OmegaConf-based hierarchical YAML)
- **Notifications**: Standardized via MyPushover, Mailer, MyTwilio classes
- **Secret I/O**: `lib/secure_io.py` — `write_secret_atomic(path, content)` for tokens we own (0o600 from birth), `ensure_secret_perms(path)` after third-party library writes (yalexs, SamsungTVWS). **All token/credential writes must go through these.**
- **File lock**: `lib/file_lock.py` — POSIX `fcntl.flock` context manager for cross-process serialization on shared resources (e.g. Ring token file used by RingSecurity + RingBeams). Yields its fd: a child given it via `pass_fds` keeps the lock after a killed parent.
- **TeslaPy Submodule**: External dependency managed as Git submodule

## formal Module (`formal/`)
- **Stack**: Quint models (Node tooling, NOT Python). `make formal-deps` then `make formal`; deliberately outside `setup`, `lint` and `test`, so the prod host never installs it.
- **Result semantics**: `quint run` is a randomized search, so "holds" is never "proved"; `quint verify` needs JDK 17+. See [formal/Logbook.md](../formal/Logbook.md) before trusting or extending a model.

## NodeCheck Module (`NodeCheck/`)
- **Purpose**: System node monitoring with continuous heartbeat tracking and automated device management
- **Testing**: Runs in isolation due to subprocess management patterns (uses pytest-forked)
- **Architecture**: Multi-process design requiring forked test execution to avoid state interference

## RachioFlume Module (`RachioFlume/`)
- **Integration**: Connects Rachio irrigation with Flume water monitoring
- **Architecture**: RachioClient, FlumeClient, WaterTrackingDB (SQLite), collector/reporter pattern
- **Usage**: `rfmanager.py` CLI with collect/status/report commands

## RingBeams Module (`RingBeams/`)
- **Purpose**: Daily battery + tamper health check for Ring Beams motion sensors and Ring Alarm sensors via Node sidecar (ring-client-api over socket.io).
- **Sidecar**: `fetch_status.js` — exit-code contract documented at top of file (0/1/2/3/4/5). Python parent maps 3 and 5 to `BeamsAuthError`; other non-zero codes raise `RuntimeError` (so a Node module-load crash never gets misclassified as "auth required").
- **Token sharing**: reads/writes the same `config/tokens/ring_auth_token.json` as RingSecurity; a POSIX flock (`lib.file_lock`) serializes the two runs so overlapping refreshes don't produce `invalid_grant`.

## RingSecurity Module (`RingSecurity/`)
- **Purpose**: Daily battery + offline health check for Ring cameras and doorbells via REST.
- **Authentication**: 2FA via `ring_manager.py auth`; token stored in `config/tokens/ring_auth_token.json`.
- **Token sharing**: see RingBeams — shared token, POSIX flock.

## SamsungFrame Module (`SamsungFrame/`)
- **Authentication**: WebSocket token-based auth, saved to `config samsung_frame.token_file`
- **Main Features**: Image upload to Frame TV, matte/border management, slideshow control, art inventory management
- **Initial Setup**: The first command that connects triggers the TV pairing prompt, token auto-saved for future use
- **Key Classes**: SamsungFrameClient, TvIo (injected I/O), ImageUploadSummary
- **Monthly album**: `frame_album.py run` picks the next album from the photo-library queue and plays it; rules in the module README
- **CLI Commands**: `frame_run.py <folder>` runs the upload pipeline (ingest, dedup, upload, cleanup, slideshow); `manage_samsung.py` has status, list-art, list-mattes, download-thumbnails, update-mattes, cycle-images, start-slideshow, reboot, delete-all, purge
- **Image Requirements**: the pipeline converts HEIC/JPG/PNG originals to <=4K JPGs under `max_image_size_mb`; the client validates each file before upload

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
