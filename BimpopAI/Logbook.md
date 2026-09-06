# BimpopAI — Logbook

Learnings and landmines. How to use this module: [README.md](README.md).

---

## Landmines

### AIY hat tokens need handholding

In dev mode tokens expire every 7 days, and then need to be purged from `~/.cache/voice_recognition/assistant-config.json`. You may also need to hack `auth_helpers.py` to get the callback URL for authentication.

### AWS App Runner is a poor fit for this stack

We initially tested the webapp locally, then moved the deploy to AWS App Runner. It fought us the whole way: its `python3.11` environment ships without `uvicorn` and refuses to install `fastapi`; the alternative environment is on Python 3.8, old enough that dependency versions start breaking. Budget real time for the runtime environment rather than the app.

---

## Deployment notes

Once we did the deploy, we used vanity domain names for everything, but this is not needed.
