# BimpopAI

Gotchas, incidents and error reference: [Logbook.md](Logbook.md).

Sample app for building an always-on sentiment analysis app.

## Layout

| Path | Role |
|---|---|
| `aiy_hat/aiy_runner.py` | Runs on a Raspberry Pi Zero with a Google AIY hat — just what I had lying around. Needs the Google Raspberry Pi image, and some handholding on tokens (see [Logbook.md](Logbook.md)). |
| `app/main.py` | ASGI FastAPI service that does the rest of the heavy lifting for the webapp. |
| `fe/streamlit_app.py` | Simple sweet front end for testing against the ASGI service. |

## Running

Launch the backend for testing as either:

```bash
python3 -m app.main 2>&1 | tee /tmp/bimpop_main.log
uvicorn app.main:app --reload --port 8080 --host 0.0.0.0 --log-level info 2>&1 | tee /tmp/bimpop_uvicorn.log
```

The front end can be locally tested with:

```bash
streamlit run fe/streamlit_app.py 2>&1 | tee /tmp/bimpop_streamlit.log
```
