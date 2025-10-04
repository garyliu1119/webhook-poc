import json

from webhook_server import app


def test_smartrecruiters_webhook():
    client = app.test_client()
    payload = {"event": "candidate.created", "candidate": {"id": 123, "name": "Alice"}}
    resp = client.post("/sr/webhook", data=json.dumps(payload), content_type="application/json")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "ok"
