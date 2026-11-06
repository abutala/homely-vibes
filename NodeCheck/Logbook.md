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
Address must be Fixed, not Rotating, for that network. The Deco admin
account is single-session ([NetworkCheck Logbook](../NetworkCheck/Logbook.md)), so the probe
takes the same `deco_admin_lock` as the NetworkCheck scripts. Each deco node logs in once per
poll, and each login evicts a person signed in to the Deco app; at one node an hour that cost
is small. If the list cannot be read, the
node reads as down: the log names the cause, and two failed polls are needed for a page.

## A host on the guest Wi-Fi cannot be pinged — probe its SSH forward (2026-11-05)

A Mac moved to the guest Wi-Fi. The guest network isolates it from the LAN, so a ping from the
prod host fails although the Mac is up. The router forwards one WAN port to its sshd. `SshNode`
connects to that forward by DNS name and checks that the reply starts with `SSH-`. The banner
comes before any authentication, so the probing host needs no key. The router does hairpin NAT:
a probe of the WAN name from the prod host got the banner in 0.21 s (2026-11-05).

The banner carries no host identity. If the dynamic DNS name pointed at another sshd, the probe
would read "up". Accepted: the router updates its own record.
