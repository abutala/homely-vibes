# NodeCheck — Logbook

Learnings and landmines. How to use this module: [README.md](README.md).

---

## A host on the guest Wi-Fi cannot be pinged — probe its SSH forward (2026-11-05)

A Mac moved to the guest Wi-Fi. The guest network isolates it from the LAN, so a ping from the
prod host fails although the Mac is up. The router forwards one WAN port to its sshd. `SshNode`
connects to that forward by DNS name and checks that the reply starts with `SSH-`. The banner
comes before any authentication, so the probing host needs no key. The router does hairpin NAT:
a probe of the WAN name from inside the home network got the banner (2026-11-05).
