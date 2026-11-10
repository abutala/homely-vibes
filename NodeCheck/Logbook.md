# NodeCheck — Logbook

Learnings and landmines. How to use this module: [README.md](README.md).

---

## A phone on the Deco list drops off for an hour or two — give the node its own threshold (2026-11-10)

A phone watched as a `deco` node left the Deco client list for two or three hourly polls many
times (it sleeps, or it leaves the house), and each time sent an emergency page. Real outages of
the same phone lasted five polls or more. `down_polls_for_alert` on the node sets how many
failed polls in a row count as down; unset, the monitor's default of two applies. Do not raise
the default: every other node would page later too.

## Isolated IoT devices — one Deco read per poll, and "unknown" is not "down" (2026-11-09)

The Deco app can isolate a device: it keeps its internet path and loses the LAN. An isolated
device does not answer ping from the prod host, so its node must be a `deco` node. Measured
2026-11-09 from a main Wi-Fi client: the IoT network alone isolates nothing (all three networks
share one subnet, and IoT clients answered ping), and the devices isolated in the app went
silent. The Deco local API does not return the isolation setting; set it in the app.

With several deco nodes, the first design had two faults (found by reading, before any page):

- **Each node logged in.** N nodes meant N logins per poll, each one able to evict the phone
  app. Now `HeartbeatMonitor` gives every deco node one `CycleCachedRead`, reset at the start
  of each poll. A failed read is kept for the poll too, so N nodes do not wait N times for
  the lock.
- **An unreadable list marked every deco node down together**: one false emergency page for
  the whole set. Now `DecoNode` raises `ProbeUnavailable`, and the monitor leaves the down
  streak as it is, so a node already confirmed down stays down. From the third unknown poll
  in a row each one counts as a failed probe, so a Deco that stays unreadable pages on the
  fourth poll. A deco node that is really down, with unknown polls between the readable ones,
  pages by the sixth poll at worst.
- **Unknown covers any error and any implausible list.** An error type the Deco client does
  not wrap, an empty list and a list of the wrong shape all read as unknown. The prod host is
  a Deco client itself, so a true list is never empty.
- **The page does not name the cause.** After four unreadable polls it says the deco nodes are
  down; the cause is in the log. With its wireless-client floor set, the uplink watchdog
  reads the same list every 10 min and alerts with the cause first.

What the Deco probe does not prove: `online` means the device is associated to the Wi-Fi. A
device with a hung application reads as up. A node that needs a deeper check (an API call, an
image) must stay reachable and keep its own type.

## A device on the guest Wi-Fi with no port forward — probe the Deco client list (2026-11-06)

An iPhone ARP node paged as down while the phone was online. It had moved to the guest Wi-Fi.
The guest network isolates its clients, so from the prod host ARP never resolves
(`INCOMPLETE`), and the phone has no port forward for `SshNode`. The Deco client list showed
it online on the `guest` interface.

A false recovery is the reverse hazard. When a host leaves its IP, another device can take
that IP by DHCP and answer the ping. Measured 2026-11-05: a different Mac took a moved host's
old IP, and the heartbeat sent "back online".

`DecoNode` asks the Deco client list for the MAC instead of probing an IP. The Deco sees
clients on every network (main, guest, IoT). The MAC must be stable: an iPhone's Private Wi-Fi
Address must be Fixed, not Rotating, for that network. If the list cannot be read, the node's
state is unknown, not down (see the 2026-11-09 entry).

**Sharing the Deco admin session.** The Deco admin account allows one session at a time: a
second login evicts the first ([NetworkCheck Logbook](../NetworkCheck/Logbook.md)).

- Our scripts on the prod host take one file lock, `deco_admin_lock`: the uplink watchdog
  (every 10 min), the IoT gatekeeper (every 5 min) and the heartbeat's one Deco read per poll. It is a
  mutex on purpose. A semaphore that let N scripts in would cause the evictions it should stop.
- The lock is local to the prod host. It cannot stop the Deco phone app (same owner account)
  or a script run from another machine. Either one can evict a script; a read then logs in
  again once. A script login can also send an open app session back to its login screen.
- The cost of the deco nodes is one login per poll, whatever their number. The gatekeeper
  already logs in every 5 min, so one more an hour adds little. No eviction problem was seen
  as of 2026-11-06.
- The read waits 30 s for the lock, less than the watchdog's 240 s. A poll that cannot get
  the lock (for example, during a mesh reboot) leaves every deco node unknown for that poll.
- Open: a dedicated Deco user for the scripts, apart from the owner account the app uses.
  Not yet tested: whether a Manager account has its own session or shares the owner's.

## A host on the guest Wi-Fi cannot be pinged — probe its SSH forward (2026-11-05)

A Mac moved to the guest Wi-Fi. The guest network isolates it from the LAN, so a ping from the
prod host fails although the Mac is up. The router forwards one WAN port to its sshd. `SshNode`
connects to that forward by DNS name and checks that the reply starts with `SSH-`. The banner
comes before any authentication, so the probing host needs no key. The router does hairpin NAT:
a probe of the WAN name from the prod host got the banner in 0.21 s (2026-11-05).

The banner carries no host identity. If the dynamic DNS name pointed at another sshd, the probe
would read "up". Accepted: the router updates its own record.
