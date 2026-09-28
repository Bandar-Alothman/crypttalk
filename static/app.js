'use strict';

/*
 * CryptTalk client.
 *
 * Key derivation:  PBKDF2-SHA-256 (310,000 iterations) from the shared passphrase
 * Encryption:      AES-256-GCM, fresh random 96-bit IV for every message
 * Payload:         JSON {v, u (username), m (message)} — encrypted together,
 *                  so the server does not learn who wrote what.
 *
 * The key is non-extractable and lives only in memory. It is discarded on
 * "Lock and leave" or when the tab is closed.
 */

const POLL_INTERVAL_MS = 2000;
const PBKDF2_ITERATIONS = 310000;
const MAX_MESSAGE_LENGTH = 2000;
const MIN_PASSPHRASE_LENGTH = 8;

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const SALT = encoder.encode('CryptTalk/v2/pbkdf2-salt');

const state = {
    key: null,
    username: '',
    lastId: 0,
    serverId: null,
    session: 0,          // bumps on join/leave so stale polls stop rendering
    polling: false,
    pollTimer: null,
    sending: false,
};

const $ = (id) => document.getElementById(id);

// ---------- encoding helpers ----------

function bytesToBase64(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
}

function base64ToBytes(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
}

// ---------- crypto ----------

async function deriveKey(passphrase) {
    const baseKey = await crypto.subtle.importKey(
        'raw', encoder.encode(passphrase), 'PBKDF2', false, ['deriveBits']
    );
    const bits = new Uint8Array(await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt: SALT, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
        baseKey,
        256
    ));

    const key = await crypto.subtle.importKey('raw', bits, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);

    // Short fingerprint so users can confirm they typed the same passphrase.
    const fpInput = new Uint8Array([...encoder.encode('CryptTalk/v2/fingerprint'), ...bits]);
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', fpInput));
    bits.fill(0);
    const hex = Array.from(digest.slice(0, 4), (b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();

    return { key, fingerprint: `${hex.slice(0, 4)}-${hex.slice(4)}` };
}

async function encryptPayload(payload) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv }, state.key, encoder.encode(JSON.stringify(payload))
    );
    return { iv: bytesToBase64(iv), ciphertext: bytesToBase64(new Uint8Array(ciphertext)) };
}

async function decryptPayload(message) {
    try {
        const plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: base64ToBytes(message.iv) },
            state.key,
            base64ToBytes(message.ciphertext)
        );
        const payload = JSON.parse(decoder.decode(plaintext));
        if (typeof payload.u !== 'string' || typeof payload.m !== 'string') return null;
        return payload;
    } catch {
        return null; // wrong passphrase, or the data was tampered with
    }
}

// ---------- UI helpers ----------

function setStatus(text, isError = false) {
    const el = $('status');
    el.textContent = text;
    el.classList.toggle('is-error', isError);
}

function setConnection(ok) {
    const el = $('connection');
    el.dataset.state = ok ? 'online' : 'offline';
    el.textContent = ok ? 'Connected' : 'Server unreachable';
}

function showJoinError(text) {
    const el = $('joinError');
    el.textContent = text;
    el.hidden = !text;
}

function formatTime(ms) {
    return new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function isNearBottom(el) {
    return el.scrollHeight - el.scrollTop - el.clientHeight < 80;
}

// Everything the user or server controls goes through textContent,
// never innerHTML, so it can't be interpreted as HTML (no XSS).
async function renderMessage(message) {
    const payload = await decryptPayload(message);
    const list = $('messages');
    const stickToBottom = isNearBottom(list);

    const item = document.createElement('article');
    item.className = 'message';
    if (!payload) item.classList.add('is-locked');
    else if (payload.u === state.username) item.classList.add('is-mine');

    const header = document.createElement('div');
    header.className = 'message-header';

    const name = document.createElement('span');
    name.className = 'message-author';
    name.dir = 'auto';
    name.textContent = payload ? payload.u : 'Unreadable message';

    const time = document.createElement('time');
    time.dateTime = new Date(message.ts).toISOString();
    time.textContent = formatTime(message.ts);

    header.append(name, time);

    const body = document.createElement('p');
    body.className = 'message-body';
    body.dir = 'auto';
    body.textContent = payload
        ? payload.m
        : 'Encrypted with a different passphrase. Your key cannot open it.';

    const cipher = document.createElement('code');
    cipher.className = 'message-cipher';
    cipher.textContent = message.ciphertext;

    item.append(header, body, cipher);
    $('emptyState').hidden = true;
    list.append(item);

    if (stickToBottom) list.scrollTop = list.scrollHeight;
}

function clearMessageView() {
    const list = $('messages');
    list.querySelectorAll('.message').forEach((el) => el.remove());
    $('emptyState').hidden = false;
}

// ---------- polling ----------

function schedulePoll(delay) {
    clearTimeout(state.pollTimer);
    state.pollTimer = setTimeout(poll, delay);
}

async function poll() {
    if (state.polling || !state.key) return;
    state.polling = true;
    const session = state.session;

    try {
        const response = await fetch(`/api/messages?after=${state.lastId}`, { cache: 'no-store' });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        if (session !== state.session) return;

        if (state.serverId && data.server_id !== state.serverId) {
            // Server restarted: ids start over, so reload from scratch.
            state.serverId = data.server_id;
            state.lastId = 0;
            clearMessageView();
            setStatus('The server restarted. Earlier messages are gone.');
            return;
        }
        state.serverId = data.server_id;

        for (const message of data.messages) {
            if (session !== state.session) return;
            if (message.id <= state.lastId) continue;
            await renderMessage(message);
            state.lastId = message.id;
        }
        setConnection(true);
    } catch (error) {
        if (session === state.session) setConnection(false);
        console.error(error);
    } finally {
        state.polling = false;
        if (state.key) schedulePoll(session === state.session ? POLL_INTERVAL_MS : 0);
    }
}

// ---------- actions ----------

async function join(event) {
    event.preventDefault();
    showJoinError('');

    const username = $('username').value.trim();
    const passphrase = $('passphrase').value;

    if (!username) return showJoinError('Enter your name.');
    if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
        return showJoinError(`Use a passphrase of at least ${MIN_PASSPHRASE_LENGTH} characters.`);
    }
    if (!window.isSecureContext || !window.crypto?.subtle) {
        return showJoinError(
            'This browser blocks encryption on insecure pages. Open the app with https:// ' +
            '(the default when you run app.py), or with http://localhost on the server computer.'
        );
    }

    const button = $('joinBtn');
    button.disabled = true;
    button.textContent = 'Deriving key';

    try {
        const { key, fingerprint } = await deriveKey(passphrase);
        state.key = key;
        state.username = username;
        state.session += 1;
        state.lastId = 0;
        state.serverId = null;

        $('passphrase').value = '';
        $('fingerprint').textContent = fingerprint;
        $('joinView').hidden = true;
        $('chatView').hidden = false;
        clearMessageView();
        setStatus('');
        $('messageInput').focus();
        schedulePoll(0);
    } catch (error) {
        showJoinError('Could not derive the key. Try again.');
        console.error(error);
    } finally {
        button.disabled = false;
        button.textContent = 'Unlock chat';
    }
}

function leave() {
    state.session += 1;
    state.key = null;
    state.lastId = 0;
    state.serverId = null;
    clearTimeout(state.pollTimer);

    clearMessageView();
    $('fingerprint').textContent = '';
    $('chatView').hidden = true;
    $('joinView').hidden = false;
    $('passphrase').focus();
}

async function send(event) {
    event.preventDefault();
    if (state.sending || !state.key) return;

    const input = $('messageInput');
    const text = input.value.trim();
    if (!text) return;
    if (text.length > MAX_MESSAGE_LENGTH) {
        return setStatus(`Messages can be up to ${MAX_MESSAGE_LENGTH} characters.`, true);
    }

    state.sending = true;
    $('sendBtn').disabled = true;

    try {
        const body = await encryptPayload({ v: 2, u: state.username, m: text });
        const response = await fetch('/api/messages', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.error || `HTTP ${response.status}`);
        }
        input.value = '';
        setStatus('Sent. It was encrypted before it left this device.');
        schedulePoll(0);
    } catch (error) {
        setStatus(`Not sent: ${error.message}`, true);
    } finally {
        state.sending = false;
        $('sendBtn').disabled = false;
        input.focus();
    }
}

// ---------- wire up ----------

document.addEventListener('DOMContentLoaded', () => {
    $('joinForm').addEventListener('submit', join);
    $('sendForm').addEventListener('submit', send);
    $('leaveBtn').addEventListener('click', leave);
    $('clearViewBtn').addEventListener('click', clearMessageView);
    $('cipherToggle').addEventListener('change', (e) => {
        $('messages').classList.toggle('show-cipher', e.target.checked);
    });
    $('username').focus();
});
