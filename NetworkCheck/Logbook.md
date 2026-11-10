# NetworkCheck — Logbook

Learnings and landmines. How to use this module: [README.md](README.md).

---

## Design notes

### The failures being fixed

**1. WAN wedge.** The Deco periodically wedges its **WAN/routing plane** (stale
WAN DHCP lease, NAT/conntrack exhaustion, DNS-proxy death) while its **switch/AP
datapath keeps working**. Symptom: LAN up, gateway pings fine, nothing routes
past it. Only a reboot clears it — and when nobody is home, nobody can pull the
plug.

**2. Radio plane death.** The mirror image, and the one nothing else notices.
The uplink is perfectly healthy — the monitoring host (the wired monitoring host) is *wired* — while
the mesh has stopped serving Wi-Fi. Every phone, camera and sensor in the house
is off the air and **every probe in the WAN path reports green**. Being on
Ethernet is exactly what makes this invisible. The signal is the Deco's own
client census: a mesh serving nobody on the radios is a mesh to reboot.

Because the LAN plane survives both, the Deco's admin API is still reachable
*during* the fault. That is the whole reason a software reboot works here.

Background: [TP-Link community — LAN client stays connected while Deco goes
red](https://community.tp-link.com/en/home/forum/topic/676614) ·
[recovery only after hours powered off, i.e. a fresh ISP
lease](https://community.tp-link.com/us/home/forum/topic/683560) ·
[TP-Link FAQ 2428](https://www.tp-link.com/us/support/faq/2428/).

### The reboot criterion, in one place

Cron runs `check` every 10 minutes. Each tick asks one question -- *does the
mesh look broken?* -- and feeds **one clock**:

1. **Internet down?** Raw `ip:port` TCP connects, no DNS. A DNS-based probe
   reports a false outage when only the Deco's DNS proxy died, and false health
   when a captive resolver answers.
2. **If the uplink is fine, are the radios?** Ask the Deco for its client list
   and count the ones that are not wired. Below `min_wireless_clients` is a
   fault. **An unreadable census counts as zero** -- see fail-closed below.
3. **Either one bad** -> the clock runs. **Fully healthy** -> the clock resets
   to zero and any queued alerts flush.
4. **Clock >= `outage_threshold_secs` (2h)** -> reboot. Then nothing for
   `retry_interval_secs` (2h).

| | check interval | dwell | onset -> reboot |
|---|---|---|---|
| Internet down | 10 min | 2h | 2h - 2h10m |
| Wi-Fi down | 10 min | 2h | 2h - 2h10m |

**Why one clock and not two.** Separate clocks each reset on their own, so a
Deco that alternates symptoms -- WAN dies for 40 min, recovers, radios die for
20 min, recover, repeat -- never accumulates enough on either one and is never
rebooted, despite being visibly sick all evening. One clock, reset only by a
fully healthy cycle, catches that. The cost is that a pure Wi-Fi fault now
waits 2h rather than 30 min; the benefit is that the flapping case is covered
at all, and the whole policy fits in a sentence.

**There is deliberately no LAN/gateway probe.** There used to be, gating the
WAN path on "does the gateway still ping." But `gateway_ip` was the Deco's own
address, so it amounted to pinging the Deco immediately before logging into it.
`_execute` already fails safe when the Deco is unreachable: the mesh listing
raises before any action is recorded, so nothing reboots and the failure is
reported. The probe only changed the wording of the alert.

> A note if you are tempted to point that probe at the upstream modem instead:
> `10.0.0.1` is one hop *past* the Deco (`ip route get` confirms `via
> 192.168.1.1`), so reaching it depends on the Deco's **routing** plane -- the
> plane that dies in a wedge. It would fail during the exact fault this exists
> for. The Deco's own address works because it exercises the **switch** plane,
> which survives.

### Failing closed on an unreadable census

If `list_clients` throws, the census returns **zero**, not "unknown" -- so an
unreadable router is treated exactly like a router serving nobody, and the
clock runs.

The alternative is worse. Treating "I could not ask" as healthy means a
permanently broken census silently disables half the watchdog forever, with no
recovery path. And a router that will not answer its own local admin API is, in
any case, a plausible reboot candidate.

No alert fires on a census failure. A transient timeout is not news -- the log
has it -- and a persistent one reaches the reboot, which has its own P1. A bad
credential still cannot cause a reboot: `_execute` lists the mesh first and
raises there.

**And no alert fires on its recovery either.** That claim above used to be true
only of the fault tick. The clock had still started, so the *next* tick sent a
P-1 reading `Recovered after 10 min (Wi-Fi down (0/25 clients on the radios))`
-- an alert that is not merely noisy but false, describing an outage that never
happened. In prod the Deco's admin API times out on roughly 2% of ticks (6 of
~260 over two days, spread across all four calls of the login handshake, never
twice in a row), so this arrived about three times a day. Upstream documents
the router behaviour and ships two knobs for it -- see
[ha-tplink-deco](https://github.com/amosyuen/ha-tplink-deco/blob/main/README.md):
*"Some routers give a lot of timeout errors... This is a problem with the
router."*

`WatchdogState.recovery_is_news` closes it. The flag is sticky for the life of
a fault window and set by anything that makes the window worth reporting: a
fault that was **not** an unreadable census (internet down, or a census that
answered honestly with too few radios), or reaching `_execute` at all -- which
covers both the reboot P1 and the "cannot reach the Deco to reboot" P1, so
neither is ever left without closure. A window made only of timeouts runs the
clock exactly as before and ends quietly.

Detection is untouched. `_census` returns `None` instead of `0` so the caller
can tell "would not answer" from "answered with nothing", and the caller
immediately maps `None` to `0`. Same clock, same threshold, same reboot, same
wording on the fault itself.

The tradeoff to know about: if a firmware update ever changes the client-list
payload so it cannot be parsed, that reads as zero clients forever. Login still
works, so it *will* reboot every 2h indefinitely. Loud, not silent -- each one
sends a P1 -- but it will not stop on its own. `max_actions_per_day` is the
brake if that ever happens.

### Transient admin-API timeouts: retry the reads, never the reboot

Every Deco request carries a 15 s timeout (`_DEFAULT_TIMEOUT`). A timeout is easy
to spot in the cron log by timing alone: a healthy tick finishes about 8 s past the
minute, and each timeout adds roughly 15 s (a one-timeout tick lands around
18–24 s). They hit any of the four handshake calls (`keys`, `auth`, `login`,
`client_list`) and do not repeat back to back.

So `DecoClient._post` retries transient transport faults — `requests.Timeout` and
`ConnectionError` only — up to `_POST_ATTEMPTS` (3) with a `_RETRY_BACKOFF_S` (1 s)
pause. An HTTP error status is a real answer from the router and is not retried.
This also keeps a single timeout on the mesh listing inside `_execute` from
aborting a reboot that is actually needed.

`reboot()` opts out with `retry=False`. A timed-out reboot may already have
landed, and re-sending it can bounce a mesh that is on its way back up. Retrying a
read is safe; retrying the reboot is not.

### Rebooting the modem

When the fault is **internet down**, the upstream Xfinity gateway is restarted
first, then the mesh. On a Wi-Fi fault it is left alone: the uplink is by
definition working, so power-cycling a healthy modem helps nobody.

It is best-effort and **never fatal**. The gateway sits one hop past the Deco,
so it may be unreachable at exactly the moment we want it; a failure is logged
and the Deco reboot follows regardless. The Deco is the proven lever, the modem
is the extra swing.

The protocol was read off the live device, not guessed:

```
POST /check.jst                                  username, password -> DUKSID cookie
GET  /restore_reboot.jst                         page embeds  var token = "...."
POST /actionHandler/ajaxSet_Reset_Restore.jst    resetInfo=["btn1","Device","admin"]
                                                 csrfp_token=<scraped token>
                                                 -> {"reboot": true}
```

**The landmine.** The same endpoint, with the same payload shape, performs a
factory wipe one identifier away:

| id | title | scope |
|---|---|---|
| **`btn1`** | **Reset the Gateway** | **`Device`** -- this is the reboot |
| `btn2` | Reset Wi-Fi Module | `Wifi` |
| `btn3` | Reset the Wi-Fi Gateway | `Wifi,Router` |
| `btn4` | Restore manufacturer defaults for Wi-Fi Only | `Wifi` |
| `btn5` | **Restore Factory settings** | `Router,Wifi,VoIP,Dect,MoCA` |
| `btn6` | Reset Password | `password` |

So `modem_client.reboot()` takes **no arguments**, the button is a module
constant, and the `ModemControl` Protocol the watchdog depends on exposes that
one verb. A test parses the module's AST and fails the build if `btn4`, `btn5`
or `btn6` ever appears in an executable position -- documenting the hazard in
the docstring stays fine, shipping it does not.

That covers our half of the contract. The device's half is checked at runtime:
immediately before the POST, the scraped page must still carry
`id="btn1"` with `title="Reset the Gateway"`, or the client refuses. The ids
belong to Comcast's firmware, not to us, and it updates unattended -- a unit
test can pin the bytes we emit but can never notice that the buttons were
renumbered underneath us. Refusing is safe: the watchdog logs it and goes on to
reboot the Deco, which is the lever that matters.

The CSRF token is scraped from the page per session; the cookie of the same
name is *not* what the handler validates.

To test it deliberately (takes the uplink down for ~4 min):

```bash
uv run python -m NetworkCheck.uplink_watchdog reboot-modem 2>&1 | tee /tmp/modem-reboot.log
```

### Getting the alert out across a reboot

Rebooting the mesh cuts the very uplink Pushover needs, so delivery is not left
to luck. Rules, each of which exists because the naive version loses the alert:

1. **Record and persist *before* the irreversible call.** `_execute()`
   enumerates the mesh, then writes `last_action_ts` and the queued alert to
   disk, and only then issues the reboot. A crash between those two points
   loses nothing.
2. **An unconfirmed reboot still counts as an action.** The router drops our
   connection *as it goes down*, so the reboot POST routinely fails after the
   router already accepted it. Treating that as "nothing happened" leaves
   `retry_interval_secs` unarmed and the next tick reboots again -- a loop that
   never lets the mesh finish booting, and that no alert escapes to report.
3. **Send inline when there is an uplink, queue when there is not.** During a
   WAN outage a send would only time out, so alerts queue in the state file and
   flush on the first cycle with a working uplink -- including a Wi-Fi-fault
   cycle, since the internet is up then. On the Wi-Fi path the alert goes out
   inline **before** the reboot, falling back to the queue if Pushover itself
   is unreachable.

Notification bodies run through `brief()`, which strips urllib3's connection
pool preamble and caps the length. This exists because the first production
census failure pushed `Deco request to {'form': 'client_list'} failed:
HTTPConnectionPool(host='192.168.1.1', port=80): Read timed out.` to a phone --
accurate, and unreadable. `DecoAPIError` messages now name the *form*, not the
params dict.

The recovery notice names both the fault and the reboot it followed
(`Recovered after 74 min (Internet down), 6 min after the watchdog rebooted the
mesh`) -- both alerts arrive on the same tick, and without that you would be
correlating timestamps to learn whether the watchdog fixed it or just watched
it end.

### Choosing `min_wireless_clients`

Ships at `0` (radio check off). There is no safe default for someone else's
house. Measure yours:

```bash
uv run python -m NetworkCheck.uplink_watchdog clients 2>&1 | tee /tmp/deco-clients.log
```

Run it across a day -- *including overnight*, when phones sleep and the count
bottoms out -- and set the floor well under the observed minimum. A deployment that
steadies at 76-82 clients on the radios can use a floor of 25 — roughly a third.

`connection_type` is `wired` / `band2_4` / `band5`; TP-Link publishes none of
this, the values come from
[ha-tplink-deco](https://github.com/amosyuen/ha-tplink-deco#client-attributes).
**Unknown counts as wireless on purpose** -- if a firmware update adds `band6`
for Wi-Fi 6E, treating it as wired would read as zero radios and reboot a
perfectly healthy house.

`clients` deliberately never prints client names: they are the household's
device names, this lands in a cron log, and the decision does not use them.
(It does print `interface`, which returns a third value, `iot`, that the
upstream docs do not list. Nothing branches on it.)

**Why not NodeCheck's down-node count?** It is the more direct signal, but
`heartbeat_nodes.py` holds its down-set in memory with nothing on disk for
another process to read -- wiring it up means inventing a shared state file and
a staleness contract. The Deco census needs neither and comes from the device
that gets rebooted. If the census proves too blunt, that is the upgrade path.

### Options considered

Recorded so nobody re-derives this. The short version: **the failure mode of the
fix must be milder than the fault it fixes**, and cutting power to your own
router fails badly.

| # | Option | Verdict | Why |
|---|---|---|---|
| 1 | **Reboot via the Deco's local admin API** | ✅ **chosen** | Reachable during the exact fault (LAN plane survives). Fails safe — a failed call changes nothing. Zero hardware. |
| 2 | Power-cut the Deco with an eWeLink/Sonoff plug | ❌ rejected | **One-way trip.** The plug rides the WiFi the Deco serves; the instant the load dies the plug loses its AP and can never be told to switch back on. |
| 3 | Sonoff `pulse` / inching as the restore timer | ❌ rejected | Wrong polarity — it is ON-then-auto-OFF. There is no OFF-then-auto-ON and no countdown endpoint. See the [itead DIY protocol doc](https://github.com/itead/Sonoff_Devices_DIY_Tools/blob/master/SONOFF%20DIY%20MODE%20Protocol%20Doc%20v1.4.md). |
| 4 | **Shelly plug with `Switch.Set?toggle_after=`** | ⏸️ viable, not built | The device schedules its own restore, so it survives the network vanishing — the only plug approach that works. Not implemented: no such hardware in this deployment, and speculative code for absent hardware is worse than none. If one is ever bought, it is a small self-contained PR; verify the host can reach it before relying on it (see Landmines). |
| 5 | Flash a Sonoff to Tasmota (`Backlog Power1 OFF; Delay …; Power1 ON`) | ⚠️ viable, not taken | Genuinely solves the restore problem on hardware already owned, but needs the plug opened and UART pads soldered. |
| 6 | Power-cycle the **modem/ONT** instead of the Deco | ⚠️ viable, not taken | Safe by construction — the Deco stays up, so the plug keeps its WiFi and can be switched back on remotely. But it does not fix a Deco wedge, which is the observed fault. |
| 7 | Rescue AP on the monitoring host (`hostapd`, same SSID) so the plug re-associates after the cut | ❌ rejected | Clever and free, but many moving parts (association, DHCP, changed IP, mDNS re-announce). If any step fails the house loses LAN *and* WAN — strictly worse than the fault. |
| 8 | Inverted deadman — plug cuts power unless the host keeps pinging it | ❌ rejected | Any crash or reboot of the monitoring host power-cycles the router. Unacceptable coupling for infrastructure. |
| 9 | TP-Link cloud / phone app remote reboot | ❌ rejected | Needs the internet that is down. |
| 10 | The Deco's own scheduled nightly auto-reboot | ❌ rejected | Blind and unconditional; does not respond to the fault and reboots on good nights too. |
| 11 | Drive an existing eWeLink plug over LAN from the monitoring host | ❌ blocked when measured | Measured then: from the wired host, ARP returned `FAILED`/`INCOMPLETE` for every IoT device tried and TCP/8081 never connected. On 2026-11-09 two IoT clients answered ARP and ping (see Landmines), so recheck before relying on this verdict. |

### Tuning the policy

All of the judgment lives in `watchdog_policy.py` — its own module precisely
because it is the only part where a wrong call has consequences. It is one pure
function over one clock; the policy no longer knows which symptom started it.
Decisions baked into the shipped default, each marked in-file:

1. **Flap handling** — `down_since` resets on a *single* fully healthy cycle.
   Fast recovery, but a Deco that flaps either symptom every few minutes still
   never accumulates enough downtime to trip the watchdog. Merging the two
   clocks narrowed that hole without closing it.
2. **Give-up** — with `max_actions_per_day: 0` it never stops, so a multi-day
   ISP outage keeps triggering reboots. Harmless while the action is a soft
   reboot; revisit if that ever changes.

### The daily gateway check

Every `auth_check_interval_secs` on a healthy cycle, `ModemClient.verify()`
logs into the gateway, fetches the reset page, confirms `btn1` is still
labelled "Reset the Gateway", and scrapes the CSRF token. It **never POSTs**.
Success is silent; failure sends a **P0** inline.

This matters more than the Deco equivalent. The modem stage only fires on a
sustained internet outage, so it can go months between real exercises, and it
has failure modes that stay invisible until that exact moment: a rotated admin
password, and a firmware update that renumbered the reset buttons. Checking
daily surfaces both while the uplink is healthy — which is also the only time
the alert can be delivered.

`verify()` and `reboot()` share `_prepare()`, so the check exercises the
identical path minus the POST and cannot drift from the thing it checks. A test
asserts they issue the same calls; if someone adds a step to `reboot()` outside
`_prepare()`, that test fails rather than the safety net silently rotting.

It runs on its own clock (`last_modem_check_ts`). Sharing the Deco's would mean
it never ran at all — a successful client census stamps that one every tick.

### The daily auth check

Every `auth_check_interval_secs` (default 24h), a **healthy** cycle logs into
the Deco and lists the mesh. Success is silent; failure sends a **P0** inline.

This closes a genuine hole. Login otherwise happens only inside `reboot_all()`
— that is, at the moment of the emergency and never before — and a failure
*there* is queued behind the very outage it was meant to fix, so it would
surface only once the outage had resolved some other way. You would learn the
safety net had failed after you no longer needed it.

A healthy cycle is the only moment we can both authenticate **and** deliver the
alert, which is why the check is deliberately skipped while the uplink is down.

It matters here specifically because the watchdog authenticates as the **owner**
account: an owner login from the Deco phone app evicts other sessions at any
time. Using a Manager account instead would reduce (not remove) that exposure.

A persistent failure alerts once per interval, not once per tick — the clock is
stamped before the attempt.

### No periodic heartbeat

There is deliberately **no periodic heartbeat**. One was built and removed: at
12 badges a day to say "nothing happened" it was pure noise, and noise that is
always ignored is not a signal. The consequence is real and worth knowing — a
watchdog that has silently died looks exactly like one with nothing to report.
The `check` cron line writes to `~/logs/uplink_watchdog.log` on every tick, so
that file's mtime is the liveness check if you ever want one.

---

### The IoT gatekeeper (2026-11-05)

**Why not the Deco's own Allow List.** Firmware 1.4.x on the XE75 Pro has Wi-Fi
Access Control with an Allow List (TP-Link FAQ 3833). It covers every SSID
except the guest network, so it would also lock the main network, where devices
change their MAC. Hence a job that blocks by MAC on the `iot` interface only.

**The admin session is one-at-a-time, and eviction is silent.** Measured on an
XE75 Pro, firmware 1.4.5: a second login with the same account evicts the
first. The evicted session's next call answers `{"data": ""}` -- not an HTTP
error and not an auth error. Before 2026-11-05 that surfaced as
`returned no data`, and in the watchdog's census it reads as zero clients and
starts the outage clock. So `DecoClient` now raises `DecoSessionLost` for it,
reads log in again once, writes never resend, and every NetworkCheck script
that logs in holds one shared file lock (`common.deco_admin_lock`). The lock
cannot stop the Deco phone app from evicting us; the read retry covers that.

**The blocklist API** (`/admin/client?form=black_list`, ported from
`roquerodrigo/tplink-deco-api`, verified on the XE75 Pro with a dummy MAC):

- `list` returns `result.client_list` as `{}` when empty and a list otherwise.
  Anything else raises -- read as empty, every tick would block and alert again.
- `block` and `unblock` answer with a plain, unencrypted `{"error_code": 0}`,
  not an encrypted `data` field. `_command` accepts both shapes.
- The block entry's `name` is the base64 name exactly as `client_list` gives it.
- The block takes the client off the Wi-Fi, not only off the internet.
  Measured 2026-11-05 with the first live block: 37 s later the phone was gone
  from `client_list` and on the blocklist.

**Fail toward blocking nothing.** A wrong block takes an IoT device offline
until a human notices, so the gatekeeper is the opposite of the watchdog's
fail-closed census: an unreadable list, an empty allowlist, an empty IoT
network or more strangers than the cap all block nothing that tick.

### Naming unknown clients (2026-11-08)

Labelling every client by hand showed what identifies a device, in the order worth trying:

- **The household's own records first.** A gadget ledger with a MAC column named most
  devices at once, offline ones too.
- **mDNS names eWeLink devices.** Each announces `eWeLink_<device id>`, the ID the app and
  Alexa show, while the app shows no MAC. Resolve it to an IP, then the Deco gives the MAC.
- **Tuya devices broadcast on UDP 6666/6667** about every 20 seconds, with their `gwId`. Newer
  firmware encrypts it under a public key derived from a fixed seed. A wired host hears them
  even from the IoT network.
- **Some cloud IDs embed the MAC.** Older Tuya `gwId`s, Meross UUIDs and Magic Home IDs end
  in it. Newer Tuya IDs do not.
- **A sibling MAC is evidence, not proof.** An August lock's Bluetooth MAC from the API was
  one below its Wi-Fi client's. Its TLS certificate named another device's maker outright.
- **A hardware MAC from a receipt never appears for a phone or Mac on a private address.**
  Labelling that MAC only makes a stale duplicate.

Two Deco behaviours caught us while doing it: `sync` reports only what it renamed this run,
so `renamed=3` for four labels meant one device was offline, not a success. And a device on
the blocklist appears to show in the app's offline list, so clearing that list brings it back.

### Capturing a client's traffic (2026-11-09)

An unknown Espressif board had no open TCP port in 1-65535, closed every common UDP discovery
port, sent no Tuya broadcast and announced no mDNS name. Only its traffic could name it, and
`client_capture.py` exists for that. What the first run showed:

- **A one-way ARP redirect is enough.** Only the client is told the gateway is at the wired
  host. The gateway keeps its true ARP entry, so replies go straight to the client and TCP still
  works. The capture shows only what the client sends, which is all that identifies it.
- **Redirects must be off on both `all` and the interface.** The kernel ORs the two
  `send_redirects` values; with either one on, it sends the client an ICMP redirect back to
  the real gateway and the capture goes empty.
- **Each forwarded frame is recorded twice** on the capturing host, in and out, with a lower
  TTL the second time. Count only frames whose Ethernet source is the client.
- **What came out:** a cloud MQTT endpoint in the DNS questions and the TLS server name, a
  hard-coded public DNS server instead of the Deco, and a new TLS session every 12 s that ended
  after about 2 s, which looks like a device whose cloud login fails. An endpoint named after an
  account ID names no vendor alone; compare it with a known device's capture.

## Landmines

- **IoT SSID reachability from the wired host varies.** An earlier measurement found a plug on
  the IoT or Guest SSID unreachable from the wired monitoring host — not slow, not filtered,
  *ARP did not resolve*. On 2026-11-09 two IoT clients answered ARP and ping from the same host.
  Verify reachability per device before trusting any plug path. The likely cause is the Deco
  app's per-device isolation, not the SSID: see the [NodeCheck Logbook](../NodeCheck/Logbook.md).
- **The Deco's request-signing RSA key is only 512-bit** (the password key is
  1024-bit). The sign text spans multiple PKCS#1 blocks, and TP-Link
  concatenates the hex of each block rather than encrypting once. Get the
  chunking wrong and login fails with an opaque error.
- **`Content-Type: application/json` with a form-encoded body.** That is what
  the router wants (`sign=<hex>&data=<urlencoded base64>`). Don't "fix" it.
- **`sign` covers `seq + len(data)`** — the length of the *base64* string,
  computed before URL-encoding.
- **`/admin/firmware?form=config_multipart` is the config restore upload.** The web UI's bundle names
  it, and that UI offers no backup route. Never POST to it to look for an export. Measured on an
  XE75 Pro, firmware 1.4.5: `read`, `get`, `list` and `load` got no data from the forms tried for
  IoT network settings, DHCP, reservations, port forwarding, IPv6, LAN IP, time, parental controls
  and QoS, so `deco_config_dump.py` cannot back those up.
- **The admin account is single-session.** Any second login -- the Deco phone
  app, or another of our scripts -- evicts the first, which then gets
  `{"data": ""}`. Reads log in again once; our scripts share one file lock.
- **`btn1` reboots the modem, `btn5` factory-resets it** — same endpoint, same
  payload shape. Read "Rebooting the modem" above before touching that module.
- **`10.0.0.1` is one hop *past* the Deco, not before it.** Anything depending
  on reaching it depends on the Deco's routing plane, which is what breaks.
- **An unreadable client census means "reboot", by design.** That is the
  fail-closed choice, not an oversight. Unknown `connection_type` values still
  count as *wireless* though — the fail-safe direction differs between "I could
  not ask" (reboot) and "I do not recognise this radio" (healthy). A firmware
  change to the client-list payload therefore becomes a 2-hourly reboot loop;
  `max_actions_per_day` is the brake.
- **Never `> /dev/null` the cron entry** — a pre-logger crash (import error,
  `uv` failure) would vanish.
- **A client rename without `client_type` changes the type.** Measured
  2026-11-06 on XE75 Pro 1.4.5: 10 of 74 renames flipped to `other` or `pc`.
  The firmware re-guesses the type from the new name. `DecoClient.rename`
  requires `client_type`: pass the value `list_clients()` returns. Names are
  cosmetic to our scripts. The gatekeeper keys on MAC, `interface` and
  `online`; NodeCheck's Deco probe on MAC and `online`; the watchdog on
  `connection_type`.
- **`client_list` read lists online clients only.** Measured 2026-11-07 on XE75
  Pro 1.4.5: `{"device_mac": "default"}` returned 81 clients, every one
  `online: true`; `{"device_mac": "offline"}` returned none; a read with no
  `params` answered HTTP 500. The Deco app's offline list is not on this local
  API, so nothing here can enumerate or forget offline clients. Labels for
  offline devices wait in config until the device reconnects.
- **A burst of admin writes times the Deco out.** Two of 74 back-to-back renames
  got a read timeout. Both writes still landed, so read back after a write;
  never resend one.

---

## References

- TP-Link community — [LAN client stays connected while Deco goes
  red](https://community.tp-link.com/en/home/forum/topic/676614) ·
  [recovery only after hours powered off, i.e. a fresh ISP
  lease](https://community.tp-link.com/us/home/forum/topic/683560)
- [TP-Link FAQ 2428](https://www.tp-link.com/us/support/faq/2428/)
- [ha-tplink-deco](https://github.com/amosyuen/ha-tplink-deco/blob/main/README.md)
  — the only public documentation of the Deco client attributes and of the
  router's timeout behaviour
- [itead SONOFF DIY mode protocol
  doc](https://github.com/itead/Sonoff_Devices_DIY_Tools/blob/master/SONOFF%20DIY%20MODE%20Protocol%20Doc%20v1.4.md)
  — checked while evaluating the plug options above
