# NetworkCheck

Gotchas, incidents and error reference: [Logbook.md](Logbook.md).

Network uplink monitoring — speed tests and external IP tracking for the home network. Reports via email and Pushover.

## Components

### `test_uplink.py` — Speed test

Runs `speedtest-cli` and classifies the link:

| Status | Condition |
|--------|-----------|
| **Good** | DL ≥ `min_dl_bw` AND UL ≥ `min_ul_bw` |
| **Degraded** | DL ≥ 80% threshold AND UL ≥ 80% threshold |
| **Bad** | Below 80% of either threshold |

Supports `--max_retries N` (waits 60s between attempts) and `--always_email` to force email delivery.

Thresholds configured in `config/default.yaml` → `network_check`:
```yaml
network_check:
  min_dl_bw: 150  # Mbps
  min_ul_bw: 4    # Mbps
```

### `external_ip_reporter.py` — IP change monitor

Fetches the current external IP from a cascade of services (ipify → icanhazip → checkip) and reports via email + Pushover. Useful for detecting dynamic IP changes.

## Notifications

Both scripts use:
- **Email** via `lib.Mailer`
- **Pushover** via the `NetworkCheck` app token (`config/local.yaml` → `pushover.tokens.NetworkCheck`)

## Prerequisites

### Speedtest CLI

The uplink test requires the [Speedtest CLI by Ookla](https://www.speedtest.net/apps/cli). It is auto-detected via `PATH`.

**macOS:**
```bash
brew install speedtest
```

**Linux (Debian/Ubuntu):**
```bash
sudo apt-get install speedtest
```

**Linux (Raspberry Pi / snap):**
```bash
sudo snap install speedtest
```

Verify with:
```bash
speedtest --version
```

## Usage

```bash
# Speed test (single attempt)
uv run python -m NetworkCheck.test_uplink

# Speed test with 3 retries
uv run python -m NetworkCheck.test_uplink --max_retries 3

# Speed test with email
uv run python -m NetworkCheck.test_uplink --always_email

# External IP report
uv run python -m NetworkCheck.external_ip_reporter
```

---

## `uplink_watchdog.py` — Deco watchdog (deadman's switch)

Detects independent failures — a wedged WAN plane, and a mesh that has stopped
serving Wi-Fi — and reboots the Deco **over its own local admin API**: no power
cut, no cloud, no hardware. What each fault looks like, and why the admin API is
still reachable during it: [Logbook.md](Logbook.md).

### Module layout

One concern per file, so the risky part is small enough to read in one sitting:

| File | Job |
|---|---|
| `probes.py` | The only code that touches the real network |
| `modem_client.py` | The upstream gateway's admin UI. Reboot only, by construction |
| `watchdog_state.py` | What survives between cron ticks, and its atomic write |
| `watchdog_policy.py` | **When to act,** for both faults. Pure function of (state, now, config) — the entire risk surface |
| `uplink_watchdog.py` | Orchestration + CLI |
| `deco_client.py` | The Deco local admin API |
| `common.py` | Notifier, invocation banner and the shared Deco admin lock |

### How it works

Cron runs `check` every few minutes. Each tick:

1. **Probe the internet** — raw `ip:port` TCP connects, no DNS. A DNS-based
   probe reports a false outage when only the Deco's DNS proxy died, and false
   health when a captive resolver answers.
2. **Count the radios** — only when the uplink is up and `min_wireless_clients`
   is set: ask the Deco for its client list and count the clients that are not
   wired. Below the floor is a fault; an unreadable census counts as zero. There
   is deliberately no LAN/gateway probe — see [Logbook.md](Logbook.md).
3. **Decide** — `should_act()` is the entire policy surface; see
   [Logbook.md](Logbook.md).
4. **Act** — reboot **every** unit in the mesh over the local API, in a single
   call (the router takes the whole `mac_list`). All of them, not just the
   master: a wedged mesh is not reliably a master-only fault, and satellites
   re-establish backhaul faster from a cold start than against a master that
   just restarted under them.
5. **Persist** — outage clock, action log and queued notifications go to
   `{logging_dir}/uplink_watchdog_state.json` via an atomic tmp + `os.replace`.
   A truncated state file would silently reset the outage clock.

On a **healthy** tick it instead runs the Wi-Fi cycle and the daily credential
check (both described in [Logbook.md](Logbook.md)).

### Configuration

Safe defaults live in `config/default.yaml` under `network_check.uplink_watchdog`;
the **admin password goes in `config/local.yaml`** (gitignored, symlinked to the
private personal-config repo — same place every other credential in this repo
lives, alongside `august:`, `ring:`, `tesla:`, `rheem:`):

```yaml
# config/local.yaml
network_check:
  uplink_watchdog:
    enabled: true
    deco_password: your_deco_admin_password   # the TP-Link *local* admin password
    deco_host: "http://192.168.x.x"
    min_wireless_clients: 25                  # measure yours with `clients` first
    modem_host: "http://10.0.0.1"             # optional second lever
    modem_password: your_gateway_admin_password
```

The watchdog ships `enabled: false`. Nothing runs until you flip it.

| Key | Default | Meaning |
|---|---|---|
| `outage_threshold_secs` | `7200` | Confirmed downtime before the first action |
| `retry_interval_secs` | `7200` | Minimum gap between actions |
| `max_actions_per_day` | `0` | `0` = unlimited. A cap keeps a multi-day ISP outage from becoming an all-night reboot loop |
| `auth_check_interval_secs` | `86400` | Credential check cadence. Only fires when the radio check is off — with it on, every healthy cycle already logs in. `0` disables |
| `probe_targets` | raw `ip:port` list | DNS-free reachability targets |
| `min_wireless_clients` | `0` | Radio-check floor. `0` disables — measure yours with `clients` first |
| `modem_host` | `""` | Upstream gateway, rebooted first on an internet fault. `""` disables |
| `modem_username` / `modem_password` | `admin` / `""` | Gateway admin credential; password in `local.yaml` |

### Usage

```bash
# One-shot check (this is what cron runs)
uv run python -m NetworkCheck.uplink_watchdog check

# Decide and log, never act -- also exercises the full login handshake
uv run python -m NetworkCheck.uplink_watchdog check --dry-run

# Dump persisted state; no side effects
uv run python -m NetworkCheck.uplink_watchdog status

# Credential smoke test: log in and list the mesh. Read-only -- the only
# command that exercises the full handshake without rebooting anything.
# Run this FIRST on any new host.
uv run python -m NetworkCheck.uplink_watchdog probe

# Wireless client census -- read-only. Run this before setting
# min_wireless_clients, and again overnight when the count bottoms out.
uv run python -m NetworkCheck.uplink_watchdog clients

# Operator escape hatches. Both take the network down; neither is read-only.
uv run python -m NetworkCheck.uplink_watchdog reboot-all      # the mesh, ~2-3 min
uv run python -m NetworkCheck.uplink_watchdog reboot-modem    # the gateway, ~4 min

# Operator escape hatch: reboot the whole mesh right now (~2-3 min outage)
uv run python -m NetworkCheck.uplink_watchdog reboot-all
```

Cron on the Linux prod host:

```
*/10 * * * * cd $HOMELY_VIBES && uv run python -m NetworkCheck.uplink_watchdog check >> ~/logs/uplink_watchdog.log 2>&1
```

### Alert priorities

Per the repo convention (`P{N}` == Pushover `priority=N`):

- **P1** — an action was taken (either fault); the Deco could not be reached to
  reboot it; a reboot that did not confirm.
- **P0** — Deco admin auth failure, or a failed gateway check (bad password, or
  `btn1` no longer labelled as the reboot). Both are chores, not emergencies.
- **P-1** — recovered (silent, informational). Skipped entirely when the whole
  fault window was an unreadable census — see fail-closed in
  [Logbook.md](Logbook.md).
- **silent** — a failed client census and a failed modem reboot. Both are
  logged; neither is worth a notification, because the clock keeps running and
  the reboot that follows carries its own P1.

### Testing

```bash
uv run python -m pytest NetworkCheck/ -v
```

Fake sessions and injected probes/clients — no `patch()`, per repo convention.
The Deco tests speak the real wire format: replies are AES-encrypted with the
client's own session key and the `sign` blob is RSA-decrypted and asserted on,
so the crypto is genuinely exercised rather than mocked away.

---

## `iot_gatekeeper.py` — IoT network gatekeeper

Blocks any device on the Deco's **IoT** network whose MAC is not on an
allowlist. The main and guest networks are never touched, so devices there may
change their MAC freely. Use it when the IoT password is widely known and the
IoT devices are too hard to re-provision with a new one. Why not the Deco's own
Allow List, and what was measured: [Logbook.md](Logbook.md).

| File | Job |
|---|---|
| `gatekeeper_policy.py` | **Who to block.** Pure function of (clients, allowlist, blocklist) |
| `iot_gatekeeper.py` | Orchestration, state, alerts, CLI |

Each tick reads the client list and the blocklist, then blocks every online,
wireless client on the `iot` interface that is not allowlisted and not already
blocked. It blocks **nothing** that tick, and alerts, when:

- the allowlist is empty, or the IoT network shows no clients;
- more unknown devices appear than `max_blocks_per_tick`;
- the Deco cannot be read (alert after 3 ticks in a row);
- the login fails (and pauses for an hour, so it cannot lock the account).

A MAC that is unknown on IoT but also present on another network is reported,
not blocked: the Deco blocklist is mesh-wide.

The block takes the device off the Wi-Fi. A blocked device stays blocked on every
later join until you unblock it.

### Setup

```bash
# 1. Print the IoT network's clients as allowlist lines (shows device names --
#    run by hand, never from cron). Delete every line that is not yours.
uv run python -m NetworkCheck.iot_gatekeeper snapshot 2>&1 | tee /tmp/iot_snapshot.log

# 2. Paste the kept lines under allowed_macs in config/local.yaml (quoted).

# 3. Watch what it would block, then set enabled: true.
uv run python -m NetworkCheck.iot_gatekeeper check --dry-run

# Undo a wrong block, then add the MAC to allowed_macs.
uv run python -m NetworkCheck.iot_gatekeeper unblock AA-BB-CC-DD-EE-FF
```

```yaml
# config/local.yaml
network_check:
  iot_gatekeeper:
    enabled: true
    allowed_macs:
      - "AA-BB-CC-DD-EE-01"  # iot_device: thermostat
```

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | `check` does nothing until set; `--dry-run` works regardless |
| `allowed_macs` | `[]` | Quoted MACs, any separator or case. One malformed entry blocks nothing and alerts |
| `max_blocks_per_tick` | `3` | More unknown devices than this in one tick blocks none of them |
| `state_file` | `iot_gatekeeper_state.json` | Failure count, login pause, alert dedupe; under `logging_dir` |

The Deco login is `uplink_watchdog`'s (`deco_host`, `deco_username`,
`deco_password`).

Cron on the Linux prod host, offset from the watchdog's `*/10`:

```
2-57/5 * * * * cd $HOMELY_VIBES && uv run python -m NetworkCheck.iot_gatekeeper check >> ~/logs/iot_gatekeeper.log 2>&1
```

Both scripts hold one file lock (`{logging_dir}/deco_admin.lock`) for as long
as they talk to the Deco: the admin account is single-session.

### Client labels (`deco_names.py`)

The Deco's client names are whatever each device advertises. `network_check.deco_names`
in `config/local.yaml` holds the labels you want, MAC to label, and every gatekeeper
`check` tick re-applies them on the same login. The Deco lists only clients that are
online, so a label for a device that is off today is applied on the first tick after it
reconnects. Labels are cosmetic: a failed rename is logged and retried next tick, never
alerted. Logs carry MACs only.

```bash
# Online clients with no label yet, as config lines (prints names -- run by hand)
uv run python -m NetworkCheck.deco_names list | tee /tmp/deco_names.txt

# Apply now instead of waiting for the next tick
uv run python -m NetworkCheck.deco_names sync --dry-run
uv run python -m NetworkCheck.deco_names sync
```

```yaml
# config/local.yaml
network_check:
  deco_names:
    "AA-BB-CC-DD-EE-01": "Fan - Basement"   # quote every MAC
```

A blank label or a malformed MAC renames nothing. A phone or laptop with a private
(rotating) Wi-Fi address keeps its label only while the device keeps that address.

### Alert priorities

- **P1** — blocked nothing because of a refusal (cap, empty IoT network, a
  malformed `allowed_macs`); the Deco unreadable for 3 ticks; a block the router
  refused. At most once a day each.
- **P0** — a device blocked, with the undo command. Also, at most once a day
  each: a MAC skipped because it is also on another network; a failed login.

Every device gets its own push, never a list: the device's self-reported name
on the first line, then its MAC and type, then what happened. A refusal pushes
once a day per unknown device. The cron log shows only MAC and type. A device
picks its own name, so trust the MAC, not the name.
