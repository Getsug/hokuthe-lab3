import os
import socket
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import crypto_client as cc
from mock_server import MockServer, frame


class GetKeyTests(unittest.TestCase):
    def test_get_key(self):
        with MockServer() as srv:
            key = cc.request_key("127.0.0.1", srv.port, "student01")
            self.assertEqual(len(key), 32)
            self.assertNotEqual(key, cc.request_key("127.0.0.1", srv.port, "student01"))

    def test_unknown_user_gets_server_error(self):
        with MockServer(users=["alice"]) as srv:
            with self.assertRaises(cc.ServerError):
                cc.request_key("127.0.0.1", srv.port, "bob")

    def test_connection_refused(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        with self.assertRaises(cc.NetworkError):
            cc.request_key("127.0.0.1", port, "u")


class FakeSock:
    """Feeds canned bytes to read_reply, in tiny chunks."""

    def __init__(self, data):
        self.data = data

    def recv(self, n):
        chunk, self.data = self.data[:min(n, 3)], self.data[min(n, 3):]
        return chunk


class ReadReplyTests(unittest.TestCase):
    def test_valid_with_payload_in_small_chunks(self):
        reply, payload = cc.read_reply(
            FakeSock(frame({"type": "decrypt_result"}, b"hello world")))
        self.assertEqual(reply["type"], "decrypt_result")
        self.assertEqual(payload, b"hello world")

    def test_missing_payload_len_means_no_payload(self):
        hb = b'{"type":"x"}'
        reply, payload = cc.read_reply(FakeSock(struct.pack(">I", len(hb)) + hb))
        self.assertEqual(payload, b"")

    def test_bad_replies(self):
        def raw(hb, extra=b""):
            return struct.pack(">I", len(hb)) + hb + extra
        cases = {
            "zero header": struct.pack(">I", 0),
            "huge header": struct.pack(">I", 5000) + b"x" * 5000,
            "not json": raw(b"not json"),
            "not object": raw(b"[1,2]"),
            "bad utf8": raw(b"\xff\xfe"),
            "negative payload": raw(b'{"payload_len":-1}'),
            "string payload": raw(b'{"payload_len":"5"}'),
            "oversized payload": raw(b'{"payload_len":1048577}'),
        }
        for name, data in cases.items():
            with self.subTest(name):
                with self.assertRaises(cc.ProtocolError):
                    cc.read_reply(FakeSock(data))

    def test_truncated(self):
        hb = b'{"type":"x","payload_len":10}'
        with self.assertRaises(cc.NetworkError):
            cc.read_reply(FakeSock(struct.pack(">I", len(hb)) + hb + b"abc"))
        with self.assertRaises(cc.NetworkError):
            cc.read_reply(FakeSock(b"\x00\x00"))


class ExpectTests(unittest.TestCase):
    def test_error_reply(self):
        with self.assertRaises(cc.ServerError):
            cc._expect({"type": "error", "detail": "boom"}, "key_result")

    def test_wrong_type(self):
        with self.assertRaises(cc.ProtocolError):
            cc._expect({"type": "verify_result"}, "key_result")


if __name__ == "__main__":
    unittest.main()
