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

---

## Error reference

### `SSLCertVerificationError: unable to get local issuer certificate`

`pyeconet` builds its own `ssl.SSLContext` and calls `load_default_certs()`, so it trusts the **system** CA store, not `certifi`. Some Linux images ship a bundle without the root that signs `rheem.clearblade.com` (DigiCert Global Root CA), and `update-ca-certificates` does not add it. Libraries that bundle `certifi` (e.g. `requests`) keep working on the same host, which hides the gap.

Confirm against the system store — `20` means the root is missing:

```bash
echo | openssl s_client -connect rheem.clearblade.com:443 -servername rheem.clearblade.com 2>&1 | grep "Verify return code"
```

Fix: point OpenSSL at certifi's bundle for the whole crontab, on its own line above the jobs. Cron does not expand variables, so write the checkout path out in place of `$HOMELY_VIBES`:

```
SSL_CERT_FILE=$HOMELY_VIBES/.venv/lib/python3.13/site-packages/certifi/cacert.pem
```

Then `uv run python Rheem/rheem_manager.py check` completes without the error.

---

## References

- `SSLContext.load_default_certs()` and `set_default_verify_paths()`: https://docs.python.org/3/library/ssl.html#ssl.SSLContext.load_default_certs
