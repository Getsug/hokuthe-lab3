import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import mock_server as ms

KEY = bytes(range(32))


class MockHmacTests(unittest.TestCase):
    """The mock's HMAC must match Section 9 on its own, independent of the client."""

    def test_hello_world(self):
        self.assertEqual(
            ms.course_hmac(KEY, b"hello world").hex(),
            "585c65e6deb8b876ed74222c5964060e707192df8ce9b91b6198de173fbfff2e")

    def test_empty(self):
        self.assertEqual(
            ms.course_hmac(KEY, b"").hex(),
            "bb7a30c41398c718904264ee91bc9ea48a36493f9e5a5577f53a1408a6ffa5b3")

    def test_not_standard_hmac(self):
        self.assertNotEqual(
            ms.course_hmac(KEY, b"hello world").hex(),
            "411b9a51e8565e1fc79643b2a6c4672f4a3c3e573c33d0995a08748cb6128e8e")


if __name__ == "__main__":
    unittest.main()
