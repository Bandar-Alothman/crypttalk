"""
CryptTalk - end-to-end encrypted chat for a local network.

All encryption and decryption happens in the browser (Web Crypto API,
AES-256-GCM with a key derived from a shared passphrase via PBKDF2).
This server never sees plaintext or keys: it only relays and stores
ciphertext blobs in memory.
"""

import argparse
import base64
import binascii
import itertools
import os
import secrets
import socket
import threading
import time
from collections import deque

from flask import Flask, jsonify, render_template, request

# =========================
# Configuration
# =========================

MAX_MESSAGES = 200                 # messages kept in memory
MAX_CIPHERTEXT_BYTES = 16 * 1024   # per message, after base64 decoding
IV_BYTES = 12                      # AES-GCM nonce size
GCM_TAG_BYTES = 16

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024  # reject oversized requests early

# Random id for this server run. Clients use it to notice a restart
# (message ids start again from 1) and reset their view.
SERVER_ID = secrets.token_hex(8)

# Optional: set this environment variable to allow clearing all messages
# through POST /api/clear with the header "X-Admin-Token: <token>".
ADMIN_TOKEN = os.environ.get("CRYPTTALK_ADMIN_TOKEN")

_messages = deque(maxlen=MAX_MESSAGES)
_lock = threading.Lock()
_next_id = itertools.count(1)


# =========================
# Helpers
# =========================

def decode_b64(value, *, exact=None, min_len=0, max_len=None):
    """Return the decoded bytes if value is valid base64 of an allowed size, else None."""
    if not isinstance(value, str):
        return None
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    if exact is not None and len(raw) != exact:
        return None
    if len(raw) < min_len:
        return None
    if max_len is not None and len(raw) > max_len:
        return None
    return raw


def get_local_ip():
    """Best-effort detection of this machine's LAN address (no packets are sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


@app.after_request
def add_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
        "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


# =========================
# Routes
# =========================

@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/messages")
def list_messages():
    """Return messages with id greater than ?after= (default 0)."""
    after = request.args.get("after", default=0, type=int)
    with _lock:
        items = [m for m in _messages if m["id"] > after]
    return jsonify(server_id=SERVER_ID, messages=items)


@app.post("/api/messages")
def post_message():
    """Store one encrypted message. The body must be JSON: {"iv": b64, "ciphertext": b64}."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="Send a JSON object with 'iv' and 'ciphertext'."), 400

    iv = data.get("iv")
    ciphertext = data.get("ciphertext")

    if decode_b64(iv, exact=IV_BYTES) is None:
        return jsonify(error=f"'iv' must be base64 of exactly {IV_BYTES} bytes."), 400
    if decode_b64(ciphertext, min_len=GCM_TAG_BYTES + 1, max_len=MAX_CIPHERTEXT_BYTES) is None:
        return jsonify(error="'ciphertext' is missing, not base64, or too large."), 400

    with _lock:
        message = {
            "id": next(_next_id),
            "iv": iv,
            "ciphertext": ciphertext,
            "ts": int(time.time() * 1000),
        }
        _messages.append(message)

    return jsonify(message), 201


@app.post("/api/clear")
def clear_messages():
    """Delete all messages. Disabled unless CRYPTTALK_ADMIN_TOKEN is set."""
    if not ADMIN_TOKEN:
        return jsonify(error="Clearing is disabled. Set CRYPTTALK_ADMIN_TOKEN to enable it."), 403

    token = request.headers.get("X-Admin-Token", "")
    if not secrets.compare_digest(token.encode(), ADMIN_TOKEN.encode()):
        return jsonify(error="Invalid admin token."), 403

    with _lock:
        _messages.clear()
    return jsonify(status="cleared")


# =========================
# Startup
# =========================

def main():
    parser = argparse.ArgumentParser(description="CryptTalk - end-to-end encrypted LAN chat")
    parser.add_argument("--host", default="0.0.0.0", help="interface to listen on (default: all)")
    parser.add_argument("--port", type=int, default=5000, help="port (default: 5000)")
    parser.add_argument(
        "--http",
        action="store_true",
        help="serve plain HTTP instead of HTTPS. Encryption in the browser then "
             "only works on http://localhost, not from other devices.",
    )
    args = parser.parse_args()

    scheme = "http" if args.http else "https"
    local_ip = get_local_ip()

    print("CryptTalk - end-to-end encrypted chat")
    print("=" * 50)
    print(f"This computer:  {scheme}://localhost:{args.port}")
    print(f"Other devices:  {scheme}://{local_ip}:{args.port}")
    print("=" * 50)
    if not args.http:
        print("Using a self-signed certificate. Browsers will show a warning the")
        print("first time; choose 'Advanced' then 'Proceed' to continue.")
    print(f"Allow incoming connections on port {args.port} in your firewall.")

    ssl_context = None if args.http else "adhoc"
    app.run(host=args.host, port=args.port, threaded=True, debug=False, ssl_context=ssl_context)


if __name__ == "__main__":
    main()
