# SmartRecruiters Webhook Listener

This is a tiny Flask app that listens for SmartRecruiters webhook POSTs on `/sr/webhook`.

Quick start (macOS / bash):

```bash
python3 -m venv .venv
source ./venv/bin/activate
pip install -r requirements.txt
python3 webhook_server.py
```

Then send a POST to http://localhost:5000/sr/webhook with a JSON payload.
