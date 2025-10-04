from flask import Flask, request, jsonify, make_response

app = Flask(__name__)

@app.route("/sr/webhook", methods=["POST"])
def smartrecruiters_webhook():
    hook_secret = request.headers.get("X-Hook-Secret")
    data = request.get_json(silent=True) or request.data.decode("utf-8")

    print(" Headers:", dict(request.headers))
    print(" Body:", data)

    if hook_secret:
        # Handshake step: respond with the same header
        response = make_response("", 200)
        response.headers["X-Hook-Secret"] = hook_secret
        return response

    # Normal event case
    return jsonify({"status": "ok"}), 200


@app.route("/", methods=["GET"])
def home():
    return "SmartRecruiters Webhook Listener Running!\n", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)

