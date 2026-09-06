# Tesla — Logbook

Learnings and landmines. How to use this module: [README.md](README.md).

---

## Incidents

### 2026-09-02 — Three days blind on fabricated data

**Symptom.** The Powerwall stopped responding to any decision point. No alert
fired. The process was healthy, polling on schedule, and logging
`Battery: 100.00%` every cycle. The failure surfaced only because a human
noticed the hardware misbehaving and went looking.

**Root cause — a three-link chain, each link individually reasonable.**

1. The Fleet API began returning `percentage_charged: 0` on every poll.
2. `sanitize_battery_percentage()` recognised the reading as bad and
   substituted an extrapolation from history — correct so far.
3. It then wrote that substitution **back into history**. History became
   entirely synthetic, and extrapolation began feeding on its own output.

The battery was near full when the API broke, so the first substitution
clamped to `100`. History filled with fabricated hundreds, the gradient went
to zero, and extrapolation returned `100` forever. A fixed point with no exit.

**What it actually did.** The failure was not inaction. Rules that test
"battery *below* a trigger" could never match at a permanent `100`, so the
overnight and shoulder rules went quiet. But `Dump surplus before end of peak`
tests *above* a falling bar, and a fabricated `100` clears that bar from
roughly 19:17 onward. It matched on every poll through peak, every evening,
and each match set the operation mode and dropped the backup reserve to 20% —
real hardware changes driven by a value the API never supplied. Whether that
did harm cannot be determined from the logs, because the only state-of-charge
field available is the broken one.

**Why nothing alerted.** The rule carries `always_notify: false`, and
production runs `manage_power.py -q` without `--send-notifications`, so both
sides of the notify condition are false. Nothing raised either: the fetch
*succeeded*, `0` being a perfectly valid float, so `fail_count` reset on every
loop. The only unconditional Pushover calls live in `main()`'s exception
handlers, which were never reached.

**Fix.** A non-positive reading is never recorded — history holds observed
values only. A run of unusable readings now pages at P1 after
`staleness_alert_after_min`, repeating at most once per
`staleness_realert_hours`. Regression tests live in `TestBatteryHistoryPoisoning`
and `TestStalenessAlert`.

---

## Landmines

### Extrapolation must never consume its own output

The moment a derived value re-enters the series it was derived from, the
estimator stops tracking reality and starts tracking itself. It will converge
on something plausible and stay there. Keep observed and derived values in
separate places; a bad sample is *no sample*, not a fabricated one.

### A warning nothing escalates is a comment with a timestamp

`"No decision point matched - is this expected?"` is in the code as a
`logger.warning`, phrased as a question. It asked that question on every poll
for three days. Log severity is not an alerting mechanism. If a condition is
worth a `warning`, decide who gets woken and when — or accept that nobody will
ever read it.

### Clamping can erase the difference between "estimate" and "no estimate"

While fixing the above, the first attempt used `pct == original_pct` to mean
"extrapolation unavailable". A negative extrapolation clamps to `0.0`, which
equals an original reading of `0.0` — so a genuine estimate of empty was
indistinguishable from having no estimate. Track availability in an explicit
flag, never by comparing values that can collide.

### `pct_min` binds, `pct_thresh` only gates

`pct_min` is the backup reserve floor written to the hardware, and the Powerwall
will not discharge below it. `pct_thresh` only sets where the trigger bar lands
at the end of the window — it decides *whether* the rule acts, never how far the
battery is allowed to fall. To change the charge you end a window with, move
`pct_min`. Moving `pct_thresh` instead changes how often the floor gets
installed at all, which is usually the opposite of the intent.

**Accepted edge (2026-09-05).** With `pct_min` above `pct_thresh`, the rule can
fire at a charge below its own floor and write a reserve above the current
charge — and a reserve above charge tells the Powerwall to charge up to it.
Grid charging is always on here (`get_powerwall_data()` raises
`Invalid powerwall config` when `can_grid_charge` is false), so that is a grid
pull at peak rates. On `Dump surplus before end of peak` the exposed band is
narrow: charge between 40 and 45 in the closing minutes before 21:00, worth a
few percent. Raising `pct_thresh` to match would close it, but would also make
the rule fire less often and so install the 45% floor less often. The band was
judged the smaller cost.

### The 45% floor holds only on the surplus path

`Dump surplus before end of peak` installs the floor only when it fires, and it
is not the only rule live in its window. `In Peak. Discharge..` runs until 19:00
with `pct_thresh: 0` and `iff_higher: true`, so it fires at any charge and
leaves the reserve at 20% when the evening window opens. From there:

| Charge at 19:00–21:00 | Rule that matches | Reserve | Ends above 45%? |
| --- | --- | --- | --- |
| high | `Dump surplus before end of peak` | 45% | yes |
| moderate | none — falls between both bars | 20%, unchanged | no |
| low | `Reserve for rest of shoulder..` (listed first, wins) | 20% | no |

`process_decision_points()` returns on the first match, and the shoulder rule is
listed ahead of the peak rule, so at low charge the peak rule is never even
evaluated. Closing the moderate and low paths means raising `pct_min` on those
rules too — deliberately not done, because the shoulder rule fires *below* its
bar and a raised floor there would write a reserve above charge far more often
than the narrow band above.

### A rule with `always_notify: false` acts silently in production

Production runs with `-q` and no `--send-notifications`, so a decision point
that does not set `always_notify: true` will change the operation mode and the
backup reserve without emitting anything. Reserve `always_notify: false` for
rules whose action you genuinely never need to hear about — and remember that
"never hear about" includes the case where the rule is firing on bad data.

### A negative `pct_gradient_per_hr` makes the bar fall, not rise

`trigger_now = pct_thresh - (pct_gradient_per_hr * hours_to_end)`. A negative
gradient therefore *adds* to the threshold, and the threshold decays toward
`pct_thresh` as the window closes. `pct_thresh` is the target at the **end** of
the window; the gradient walks it backwards in time. A consequence worth
knowing: `Dump surplus before end of peak` opens at a bar of 110%, so it cannot
fire for the first stretch of its own window.

### `pct_min_trail_stop: 0` is off, and the falsy check is why

`apply_decision_point()` guards the trailing stop with
`if decision_point.pct_min_trail_stop:`. Zero is falsy, so the block is
skipped. That is load-bearing: with a zero trail stop the loop would be
`while battery >= desired_min + 0: desired_min += 0`, which never terminates.
Do not "tighten" that guard to `is not None`.

### `0` is a valid float, so a broken API looks like a healthy poll

Nothing raised for three days because the API returned a well-formed response
containing a meaningless number. Retry counters keyed on exceptions cannot see
this class of failure. Validate the *content* of a response, not just its
arrival.

### A restart during an outage is the dangerous moment

With history empty and the API returning `0`, the old code returned `0.0` — and
`0%` matches every low-battery decision point at once, driving real reserve
changes off a value never observed. `sanitize_battery_percentage()` now returns
`None` when it cannot produce a trustworthy value, and the loop skips the cycle.

---

## Error reference

### `Tesla token expired - run: uv run Tesla/tesla_auth.py`

Refresh token expired (>90 days unused) or revoked. Re-run the OAuth flow:

```bash
uv run Tesla/tesla_auth.py 2>&1 | tee /tmp/tesla-auth.log
```

### `412 invalid public key` on `--partner-login`

The URL `https://<domain>/.well-known/appspecific/com.tesla.3p.public-key.pem`
isn't reachable or doesn't match the public key Tesla recorded at
app-registration time. Re-verify with `curl -I` and check `.nojekyll` is present.

### `403 forbidden, see https://developer.tesla.com/docs/fleet-api`

The legacy Owner API host. Indicates the module fell back to old code or the SDK
isn't installed. `BASE_URL` should never appear in `tesla_client.py` anymore.
Reinstall with `uv sync`.

### `redirect_uri not registered for this client_id`

The redirect URI in `config/local.yaml` (`fleet_redirect_uri`) doesn't match
what's registered at developer.tesla.com. Update one or the other so they match
exactly (including trailing slash).

### `operation: None` in logs

Pre-existing artifact, not a Fleet API regression. The live-status endpoint
sometimes omits `operation`; `manage_power.py` falls back to `cached_op_mode`.
Note that this predates the 2026-09-02 incident above and is unrelated to it —
the module has tolerated a silently-dropped API field before.

---

## References

- Migration plan that drove the Fleet API implementation:
  `~/.claude/plans/uv-run-tesla-manage-power-py-is-cryptic-sloth.md`
