# 🔐 CryptTalk

End-to-end encrypted group chat for a local network, built with Flask and the browser's Web Crypto API.

Messages are encrypted **in the sender's browser** and decrypted **in the recipient's browser**. The server only relays and stores ciphertext; it never sees message text, usernames, or keys.

> Graduation project. Built to demonstrate applied cryptography in a real web application, not as a replacement for audited messengers like Signal.

<!-- Add a screenshot: save it as docs/screenshot.png and uncomment the line below -->
<!-- ![CryptTalk screenshot](docs/screenshot.png) -->

## Features

- **Client-side AES-256-GCM encryption** with a fresh random 96-bit IV for every message
- **PBKDF2-SHA-256 key derivation** (310,000 iterations) from a shared passphrase
- **Zero-knowledge server**: stores only `{id, iv, ciphertext, timestamp}`
- **Tamper detection**: GCM authentication rejects any modified message
- **Key fingerprint** so participants can confirm they typed the same passphrase
- **"Show what the server sees"** toggle that reveals the raw ciphertext next to each message
- Messages from other passphrases appear as unreadable, which demonstrates key separation
- Hardened against XSS: all message content is rendered with `textContent`, plus a strict Content Security Policy
- HTTPS out of the box (self-signed certificate) so it works across devices on the LAN
- Arabic and English text supported (automatic text direction)
- Light and dark mode

## How it works

```
 Sender's browser                    Flask server                   Recipient's browser
 ────────────────                    ────────────                   ───────────────────
 passphrase ──PBKDF2──► key                                          passphrase ──PBKDF2──► key
 {user, text} ──AES-GCM(key, iv)──►  stores {iv, ciphertext}  ──►   AES-GCM decrypt(key, iv)
                                     (cannot decrypt)                 └─► {user, text}
```

1. Each participant enters a name and the **shared passphrase**, agreed on in person.
2. The browser derives a 256-bit AES key with PBKDF2. The key is non-extractable and kept only in memory.
3. When sending, the browser encrypts `{username, message}` with AES-256-GCM and posts only the IV and ciphertext.
4. Every 2 seconds, clients poll `/api/messages?after=<last id>` and decrypt new messages locally.
5. A message encrypted with a different passphrase fails GCM authentication and is shown as unreadable.

## Getting started

Requires Python 3.9+.

```bash
git clone https://github.com/Bandar-Alothman/crypttalk.git
cd crypttalk
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

The console prints two addresses:

```
This computer:  https://localhost:5000
Other devices:  https://192.168.1.20:5000
```

Open the second address on other devices on the same Wi-Fi. Because the certificate is self-signed, the browser shows a warning the first time: choose **Advanced → Proceed**. Allow port 5000 through your firewall if other devices cannot connect.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `5000` | Port to listen on |
| `--host` | `0.0.0.0` | Interface to listen on |
| `--http` | off | Serve plain HTTP. Browsers only allow Web Crypto on `http://localhost`, so other devices will not be able to encrypt. |

### Clearing all messages (optional)

Clearing is disabled by default so no one on the network can wipe the chat. To enable it:

```bash
export CRYPTTALK_ADMIN_TOKEN="choose-a-long-random-token"   # Windows: set CRYPTTALK_ADMIN_TOKEN=...
python app.py
```

```bash
curl -k -X POST https://localhost:5000/api/clear -H "X-Admin-Token: choose-a-long-random-token"
```

## API

| Method | Endpoint | Body / query | Description |
|--------|----------|--------------|-------------|
| `GET` | `/api/messages?after=<id>` | | Messages with id greater than `after` |
| `POST` | `/api/messages` | `{"iv": "<base64>", "ciphertext": "<base64>"}` | Store one encrypted message |
| `POST` | `/api/clear` | header `X-Admin-Token` | Delete all messages (only if enabled) |

The server validates that `iv` is exactly 12 bytes and `ciphertext` is valid base64 under 16 KB, so it cannot be used to store plaintext by accident.

## Project structure

```
crypttalk/
├── app.py              # Flask server: relays ciphertext, validation, security headers
├── requirements.txt
├── templates/
│   └── index.html      # Page layout (no inline scripts or styles)
└── static/
    ├── app.js          # Key derivation, encryption, decryption, polling, rendering
    └── style.css
```

## Security model and limitations

What CryptTalk protects against:

- The server operator or anyone with access to the server reading messages
- Someone on the network reading traffic (HTTPS + end-to-end encryption)
- Modified or forged ciphertext (rejected by AES-GCM authentication)
- Script injection through usernames or messages

What it does **not** protect against, and how a production system would address it:

- **Weak passphrases.** Security depends entirely on the passphrase. PBKDF2 slows down guessing but cannot save a short or common one.
- **Metadata.** The server sees when messages are sent, their approximate size, and the sender's IP address.
- **No per-user identity.** Anyone with the passphrase can post under any name. Real messengers use per-user key pairs and signatures.
- **No forward secrecy.** If the passphrase leaks, all past messages encrypted with it can be decrypted. Protocols like Signal's Double Ratchet rotate keys per message.
- **Static salt.** The PBKDF2 salt is fixed for the app. A random salt per chat room would stop precomputed attacks across different deployments.
- **Trusted server code.** The server delivers the JavaScript, so a malicious server could send modified code that leaks the key. This is a known limitation of all browser-based end-to-end encryption.
- **Development server.** Flask's built-in server and the self-signed certificate are fine for a LAN demo but not for the internet. Deploy behind a WSGI server (e.g. Gunicorn) with a real certificate.
- Messages are stored in memory only (last 200) and are lost when the server restarts.

## Tech stack

Python · Flask · Web Crypto API (AES-GCM, PBKDF2) · vanilla JavaScript · HTML/CSS
