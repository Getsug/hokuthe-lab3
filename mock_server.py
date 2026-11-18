"""Local mock of the crypto server, for integration tests.

Speaks the framing from crypto_message_spec_v2.md on 127.0.0.1. It is
written independently of crypto_client.py (no imports from it) so that
client and server cannot share a bug.
"""

import base64
import hashlib
import json
import os
import socketserver
import struct
import threading

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAX_HEADER = 1000
MAX_PAYLOAD = 1_048_576
USERNAME_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-")

def _raw_header(hb):
    return struct.pack(">I", len(hb)) + hb


# Deliberately invalid replies, for testing the client's reply validation.
BAD_REPLIES = {
    "bad_reply": lambda: _raw_header(b"this is not json"),
    "wrong_type": lambda: frame({"type": "verify_result", "result": "VERIFIED"}),
    "oversized_reply": lambda: _raw_header(
        b'{"type":"decrypt_result","payload_len":2000000}'),
    "bad_result": lambda: frame({"type": "verify_result", "result": "MAYBE"}),
}

BEHAVIORS = ("normal", "tamper_decrypt", "always_error", "drop_connection",
             "drop_mid_reply", "timeout") + tuple(BAD_REPLIES)


class _Closed(Exception):
    pass


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise _Closed()
        buf += chunk
    return buf


def frame(header, payload=b""):
    header = dict(header, payload_len=len(payload))
    hb = json.dumps(header, separators=(",", ":")).encode("utf-8")
    return struct.pack(">I", len(hb)) + hb + payload


def error_reply():
    return frame({"type": "error", "detail": "error processing request"})


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        server = self.server.owner
        sock = self.request
        sock.settimeout(60)
        mode = server.behavior
        if mode == "drop_connection":
            return                       # close without reading or replying
        try:
            if mode == "timeout":
                server.stopping.wait(60)  # accept, read nothing, never reply
                return
            if mode == "always_error":
                self.process(sock, server)   # consume the request, then refuse
                reply = error_reply()
            else:
                reply = self.process(sock, server)
            if mode == "drop_mid_reply" and reply is not None:
                reply = reply[:6]        # partial reply, then close
            elif mode in BAD_REPLIES:
                reply = BAD_REPLIES[mode]()
        except (_Closed, OSError):
            return
        if reply is not None:
            try:
                sock.sendall(reply)
            except OSError:
                pass

    def process(self, sock, server):
        (hlen,) = struct.unpack(">I", _recv_exact(sock, 4))
        if hlen > MAX_HEADER or hlen == 0:
            return error_reply()
        try:
            header = json.loads(_recv_exact(sock, hlen).decode("utf-8"))
        except ValueError:
            return error_reply()
        if not isinstance(header, dict):
            return error_reply()
        plen = header.get("payload_len", 0)
        if not isinstance(plen, int) or isinstance(plen, bool) or plen < 0 \
                or plen > MAX_PAYLOAD:
            return error_reply()
        payload = _recv_exact(sock, plen) if plen else b""

        username = header.get("username")
        if not isinstance(username, str) or not 1 <= len(username) <= 32 \
                or not set(username) <= USERNAME_CHARS:
            return error_reply()
        if server.users is not None and username not in server.users:
            return error_reply()

        kind = header.get("type")
        if kind == "get_key":
            return frame({"type": "key_result",
                          "key": base64.b64encode(os.urandom(32)).decode()})
        if kind == "decrypt":
            try:
                key = base64.b64decode(header["key"], validate=True)
                if len(key) != 32 or len(payload) < 28:
                    return error_reply()
                plain = AESGCM(key).decrypt(payload[:12], payload[12:], None)
            except Exception:
                return error_reply()
            if server.behavior == "tamper_decrypt":
                plain = bytes([plain[0] ^ 1]) + plain[1:] if plain else b"\x00"
            return frame({"type": "decrypt_result"}, plain)
        if kind == "verify_hmac":
            try:
                key = base64.b64decode(header["key"], validate=True)
                claimed = base64.b64decode(header["hmac"], validate=True)
            except Exception:
                return error_reply()
            if len(key) != 32 or len(claimed) != 32:
                return error_reply()
            ok = claimed == course_hmac(key, payload)
            return frame({"type": "verify_result",
                          "result": "VERIFIED" if ok else "FAILED"})
        return error_reply()


def course_hmac(key, data):
    """Independent implementation of spec Section 6 (not shared with the client)."""
    inner_key = int.from_bytes(key, "big") ^ int.from_bytes(b"\x36" * 32, "big")
    outer_key = int.from_bytes(key, "big") ^ int.from_bytes(b"\x5c" * 32, "big")
    h_in = hashlib.new("sha256")
    h_in.update(inner_key.to_bytes(32, "big"))
    h_in.update(data)
    h_out = hashlib.new("sha256")
    h_out.update(outer_key.to_bytes(32, "big"))
    h_out.update(h_in.digest())
    return h_out.digest()


class _TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class MockServer:
    """Start/stop-able mock server. `users=None` accepts any valid username."""

    def __init__(self, behavior="normal", users=None, port=0):
        if behavior not in BEHAVIORS:
            raise ValueError(f"unknown behavior {behavior!r}")
        self.behavior = behavior
        self.users = set(users) if users is not None else None
        self._server = _TCPServer(("127.0.0.1", port), _Handler)
        self._server.owner = self
        self.port = self._server.server_address[1]
        self.stopping = threading.Event()
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self):
        self.stopping.set()
        self._server.shutdown()
        self._server.server_close()
        if self._thread:
            self._thread.join(timeout=5)

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Local mock crypto server")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()
    srv = MockServer(port=args.port).start()
    print(f"Mock server listening on 127.0.0.1:{srv.port} (Ctrl+C to stop)")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        srv.stop()
