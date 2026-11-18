import json
import os
import socket
import struct
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import crypto_client as cc


class FramingVectorTests(unittest.TestCase):
    def test_section9_vector(self):
        built = cc.build_request({"type": "get_key", "username": "student01"})
        self.assertEqual(built.hex(), cc.FRAMING_VECTOR_HEX)
        self.assertEqual(built[:4], b"\x00\x00\x00\x39")
        self.assertEqual(len(built) - 4, 57)

    def test_check_function(self):
        ok, _ = cc.check_framing_vector()
        self.assertTrue(ok)

    def test_payload_len_set_and_last(self):
        built = cc.build_request({"type": "decrypt", "username": "u", "payload_len": 999},
                                 b"abc")
        (hlen,) = struct.unpack(">I", built[:4])
        header = json.loads(built[4:4 + hlen])
        self.assertEqual(header["payload_len"], 3)
        self.assertEqual(list(header)[-1], "payload_len")
        self.assertEqual(built[4 + hlen:], b"abc")

    def test_length_counts_bytes_not_characters(self):
        built = cc.build_request({"type": "x", "username": "u", "note": "é" * 10})
        (hlen,) = struct.unpack(">I", built[:4])
        self.assertEqual(hlen, len(built) - 4)

    def test_header_too_long(self):
        with self.assertRaises(cc.ValidationError):
            cc.build_request({"type": "x", "username": "u", "pad": "a" * 1000})


class RecvExactTests(unittest.TestCase):
    def test_reassembles_short_reads(self):
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)

        def sender():
            for byte in b"hello world":
                a.send(bytes([byte]))

        t = threading.Thread(target=sender)
        t.start()
        self.assertEqual(cc.recv_exact(b, 11), b"hello world")
        t.join()

    def test_zero_bytes(self):
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        self.assertEqual(cc.recv_exact(b, 0), b"")

    def test_closed_early(self):
        a, b = socket.socketpair()
        self.addCleanup(b.close)
        a.send(b"abc")
        a.close()
        with self.assertRaises(cc.NetworkError):
            cc.recv_exact(b, 10)


if __name__ == "__main__":
    unittest.main()
