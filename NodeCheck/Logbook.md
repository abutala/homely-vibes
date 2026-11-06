# NodeCheck — Logbook

Learnings and landmines. How to use this module: [README.md](README.md).

---

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
Address must be Fixed, not Rotating, for that network. If the list cannot be read, the node
reads as down: the log names the cause, and two failed polls are needed for a page.

**Sharing the Deco admin session.** The Deco admin account allows one session at a time: a
second login evicts the first ([NetworkCheck Logbook](../NetworkCheck/Logbook.md)).

- Our scripts on the prod host take one file lock, `deco_admin_lock`: the uplink watchdog
  (every 10 min), the IoT gatekeeper (every 5 min) and each deco node (once per poll). It is a
  mutex on purpose. A semaphore that let N scripts in would cause the evictions it should stop.
- The lock is local to the prod host. It cannot stop the Deco phone app (same owner account)
  or a script run from another machine. Either one can evict a script; a read then logs in
  again once. A script login can also send an open app session back to its login screen.
- The cost of `DecoNode` is one login per deco node per poll. The gatekeeper already logs in
  every 5 min, so one node an hour adds little. No eviction problem was seen as of 2026-11-06.
- `DecoNode` waits 30 s for the lock, less than the watchdog's 240 s. A poll that cannot get
  the lock (for example, during a mesh reboot) reads as down once; flap suppression absorbs it.
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
