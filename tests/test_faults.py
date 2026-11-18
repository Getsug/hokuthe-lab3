"""Error-path tests: mock-server fault modes and raw malformed requests."""

import json
import os
import socket
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import crypto_client as cc
from mock_server import MockServer

KEY = bytes(range(32))


def raw_exchange(port, data, read=True):
    """Send raw bytes to the mock and return (reply_header, payload) or None."""
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(data)
        if not read:
            return None
        return cc.read_reply(s)


def framed(header, payload=b""):
    hb = json.dumps(header, separators=(",", ":")).encode()
    return struct.pack(">I", len(hb)) + hb + payload


class ClientFaultTests(unittest.TestCase):
    """The client must turn each fault into a clear ClientError."""

    def setUp(self):
        self._timeout = cc.SOCKET_TIMEOUT
        cc.SOCKET_TIMEOUT = 0.7        # keep timeout tests fast
        self.addCleanup(setattr, cc, "SOCKET_TIMEOUT", self._timeout)

    def run_get_key(self, behavior):
        with MockServer(behavior=behavior) as srv:
            return cc.request_key("127.0.0.1", srv.port, "u")

    def test_always_error(self):
        with self.assertRaises(cc.ServerError) as cm:
            self.run_get_key("always_error")
        self.assertIn("error processing request", str(cm.exception))

    def test_drop_connection(self):
        with self.assertRaises(cc.NetworkError):
            self.run_get_key("drop_connection")

    def test_drop_mid_reply(self):
        with self.assertRaises(cc.NetworkError):
            self.run_get_key("drop_mid_reply")

    def test_timeout(self):
        with self.assertRaises(cc.NetworkError) as cm:
            self.run_get_key("timeout")
        self.assertIn("timeout", str(cm.exception).lower())

    def test_garbage_reply(self):
        with self.assertRaises(cc.ProtocolError):
            self.run_get_key("bad_reply")

    def test_wrong_reply_type(self):
        with self.assertRaises(cc.ProtocolError):
            self.run_get_key("wrong_type")

    def test_oversized_reply(self):
        with MockServer(behavior="oversized_reply") as srv:
            with self.assertRaises(cc.ProtocolError):
                cc.request_decrypt("127.0.0.1", srv.port, "u", KEY, b"x" * 28)

    def test_unknown_verify_result(self):
        with MockServer(behavior="bad_result") as srv:
            with self.assertRaises(cc.ProtocolError):
                cc.request_verify("127.0.0.1", srv.port, "u", KEY, b"m" * 32, b"d")

    def test_verify_error_differs_from_failed(self):
        """An error reply raises; a FAILED verdict returns False (spec 4.3)."""
        with MockServer(behavior="always_error") as srv:
            with self.assertRaises(cc.ServerError):
                cc.request_verify("127.0.0.1", srv.port, "u", KEY, b"m" * 32, b"d")
        with MockServer() as srv:
            self.assertFalse(
                cc.request_verify("127.0.0.1", srv.port, "u", KEY, b"m" * 32, b"d"))

    def test_workflows_surface_faults(self):
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "f.txt")
            with open(src, "wb") as f:
                f.write(b"data")
            with MockServer(behavior="drop_connection") as srv:
                conn = cc.Connection("127.0.0.1", srv.port, "u")
                with self.assertRaises(cc.NetworkError):
                    cc.aes_roundtrip(conn, KEY, src, d)
                with self.assertRaises(cc.NetworkError):
                    cc.hmac_compute_and_verify(conn, KEY, src, d)


class MockServerBehaviorTests(unittest.TestCase):
    """The mock itself must refuse bad requests like the real server."""

    def test_malformed_requests_get_error(self):
        cases = {
            "not json": struct.pack(">I", 8) + b"not json!",
            "json array": struct.pack(">I", 5) + b"[1,2]",
            "unknown type": framed({"type": "nope", "username": "u", "payload_len": 0}),
            "bad username": framed({"type": "get_key", "username": "bad name",
                                    "payload_len": 0}),
            "missing username": framed({"type": "get_key", "payload_len": 0}),
            "header too long": struct.pack(">I", 1001) + b"x" * 1001,
            "decrypt no key": framed({"type": "decrypt", "username": "u",
                                      "payload_len": 0}),
            "verify no hmac": framed({"type": "verify_hmac", "username": "u",
                                      "key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
                                      "payload_len": 0}),
            "negative payload_len": framed({"type": "get_key", "username": "u",
                                            "payload_len": -1}),
        }
        with MockServer() as srv:
            for name, data in cases.items():
                with self.subTest(name):
                    header, _ = raw_exchange(srv.port, data)
                    self.assertEqual(header["type"], "error")

    def test_oversized_payload_len_rejected_before_payload(self):
        with MockServer() as srv:
            data = framed({"type": "decrypt", "username": "u",
                           "key": cc.b64encode(KEY), "payload_len": 1_048_577})
            try:
                header, _ = raw_exchange(srv.port, data)
                self.assertEqual(header["type"], "error")
            except cc.NetworkError:
                pass    # spec 8: a client may instead see the connection reset

    def test_unlisted_user_rejected(self):
        with MockServer(users=["alice"]) as srv:
            header, _ = raw_exchange(
                srv.port, framed({"type": "get_key", "username": "bob", "payload_len": 0}))
            self.assertEqual(header["type"], "error")

    def test_wrong_key_length_and_corrupt_file(self):
        with MockServer() as srv:
            blob = cc.aes_encrypt(KEY, b"hello")
            for key, data in [(b"short", blob), (KEY, blob[:-1] + bytes([blob[-1] ^ 1])),
                              (KEY, b"tiny")]:
                header, _ = raw_exchange(srv.port, framed(
                    {"type": "decrypt", "username": "u", "key": cc.b64encode(key)}, data))
                self.assertEqual(header["type"], "error")

    def test_invalid_behavior_name(self):
        with self.assertRaises(ValueError):
            MockServer(behavior="bogus")


if __name__ == "__main__":
    unittest.main()
