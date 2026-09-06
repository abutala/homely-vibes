# Rheem — Logbook

Learnings and landmines. How to use this module: [README.md](README.md).

---

## Landmines

### Unofficial API

`pyeconet` reverse-engineers Rheem's ClearBlade cloud (`rheem.clearblade.com`). Rheem can change endpoints without notice; the library could break at any time.

### Discrete levels only

The tank exposes 0/33/66/100, not a continuous percentage. Thresholds must align to these levels (defaults: low=33, mid=66).

### Some tanks don't report `@HOTWATER`

Availability is `None`; the monitor skips them with a debug log. No alert is fired for unsupported tanks.
