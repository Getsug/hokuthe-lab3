import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import crypto_client as cc


class UsernameTests(unittest.TestCase):
    def test_valid(self):
        for name in ["a", "student01", "A_b.c-d", "x" * 32]:
            self.assertEqual(cc.validate_username(name), name)

    def test_invalid(self):
        for name in ["", "x" * 33, "bad name", "bad/name", "name\n", "é", "a@b", None]:
            with self.subTest(name=name):
                with self.assertRaises(cc.ValidationError):
                    cc.validate_username(name)


class HostPortTests(unittest.TestCase):
    def test_host(self):
        for h in ["127.0.0.1", "localhost", "server.example.com"]:
            self.assertEqual(cc.validate_host(h), h)
        for h in ["", "  ", "a b", "http://x", "x/y"]:
            with self.subTest(host=h):
                with self.assertRaises(cc.ValidationError):
                    cc.validate_host(h)

    def test_port(self):
        self.assertEqual(cc.validate_port("8080"), 8080)
        self.assertEqual(cc.validate_port(" 1 "), 1)
        self.assertEqual(cc.validate_port(65535), 65535)
        for p in ["0", "65536", "-1", "abc", "", "80.5"]:
            with self.subTest(port=p):
                with self.assertRaises(cc.ValidationError):
                    cc.validate_port(p)

    def test_connection(self):
        self.assertEqual(cc.validate_connection("h", "8080", "u"), ("h", 8080, "u"))
        with self.assertRaises(cc.ValidationError):
            cc.validate_connection("h", "8080", "bad name")


class ReadInputFileTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def path(self, name, data):
        p = os.path.join(self.dir.name, name)
        with open(p, "wb") as f:
            f.write(data)
        return p

    def test_exact_limit_and_empty(self):
        p = self.path("a.bin", b"x" * cc.AES_MAX_PLAINTEXT)
        self.assertEqual(len(cc.read_input_file(p, cc.AES_MAX_PLAINTEXT)),
                         cc.AES_MAX_PLAINTEXT)
        self.assertEqual(cc.read_input_file(self.path("e", b""), 10), b"")

    def test_over_limit_names_file_and_size(self):
        p = self.path("big.bin", b"x" * (cc.AES_MAX_PLAINTEXT + 1))
        with self.assertRaises(cc.ValidationError) as cm:
            cc.read_input_file(p, cc.AES_MAX_PLAINTEXT)
        self.assertIn("big.bin", str(cm.exception))
        self.assertIn(f"{cc.AES_MAX_PLAINTEXT + 1:,}", str(cm.exception))

    def test_workflow_limits_differ(self):
        data = b"x" * (cc.AES_MAX_PLAINTEXT + 1)
        p = self.path("mid.bin", data)
        self.assertEqual(cc.read_input_file(p, cc.HMAC_MAX_FILE), data)

    def test_missing_and_directory(self):
        with self.assertRaises(cc.FileAccessError):
            cc.read_input_file(os.path.join(self.dir.name, "nope"), 10)
        with self.assertRaises(cc.FileAccessError):
            cc.read_input_file(self.dir.name, 10)


if __name__ == "__main__":
    unittest.main()
