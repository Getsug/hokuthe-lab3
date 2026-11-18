import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import crypto_client as cc

KEY = bytes(range(32))
KEY_B64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="


class AesTests(unittest.TestCase):
    def test_section9_vector(self):
        blob = cc.aes_encrypt(KEY, b"hello world", bytes(range(12)))
        self.assertEqual(len(blob), 39)
        self.assertEqual(blob.hex(), cc.AES_VECTOR_BLOB_HEX)
        self.assertEqual(
            blob.hex(),
            "000102030405060708090a0b2f67ba77aac5b574ff2df305301c56437e2377b9"
            "8ef3961c271928")

    def test_decrypt_vector(self):
        self.assertEqual(cc.aes_decrypt(KEY, bytes.fromhex(cc.AES_VECTOR_BLOB_HEX)),
                         b"hello world")

    def test_check_function(self):
        self.assertTrue(cc.check_aes_vector()[0])

    def test_size_and_fresh_nonce(self):
        for n in (0, 1, 1000):
            self.assertEqual(len(cc.aes_encrypt(KEY, b"x" * n)), n + 28)
        a, b = cc.aes_encrypt(KEY, b"same"), cc.aes_encrypt(KEY, b"same")
        self.assertNotEqual(a[:12], b[:12])

    def test_roundtrip_empty(self):
        self.assertEqual(cc.aes_decrypt(KEY, cc.aes_encrypt(KEY, b"")), b"")

    def test_check_detects_broken_implementation(self):
        original = cc.aes_encrypt
        try:
            cc.aes_encrypt = lambda key, pt, nonce=None: b"\x00" * 39
            ok, msg = cc.check_aes_vector()
        finally:
            cc.aes_encrypt = original
        self.assertFalse(ok)
        self.assertIn("incorrect", msg)


class HmacTests(unittest.TestCase):
    HELLO = "585c65e6deb8b876ed74222c5964060e707192df8ce9b91b6198de173fbfff2e"
    EMPTY = "bb7a30c41398c718904264ee91bc9ea48a36493f9e5a5577f53a1408a6ffa5b3"
    STANDARD = "411b9a51e8565e1fc79643b2a6c4672f4a3c3e573c33d0995a08748cb6128e8e"

    def test_section9_hello_world(self):
        mac = cc.custom_hmac(KEY, b"hello world")
        self.assertEqual(mac.hex(), self.HELLO)
        self.assertEqual(cc.b64encode(mac), "WFxl5t64uHbtdCIsWWQGDnBxkt+M6bkbYZjeFz+//y4=")

    def test_section9_empty(self):
        self.assertEqual(cc.custom_hmac(KEY, b"").hex(), self.EMPTY)

    def test_inner_hash_and_derived_keys(self):
        ki = bytes(b ^ 0x36 for b in KEY)
        ko = bytes(b ^ 0x5C for b in KEY)
        self.assertEqual(ki.hex(),
                         "36373435323330313e3f3c3d3a3b383926272425222320212e2f2c2d2a2b2829")
        self.assertEqual(ko.hex(),
                         "5c5d5e5f58595a5b54555657505152534c4d4e4f48494a4b4445464740414243")
        self.assertEqual(cc.sha256(ki + b"hello world").hex(),
                         "05001c1f5260531db22d744e1629e7450903558c545cdd514bea3f555684deac")

    def test_differs_from_standard_hmac(self):
        self.assertNotEqual(cc.custom_hmac(KEY, b"hello world").hex(), self.STANDARD)

    def test_rejects_wrong_key_length(self):
        with self.assertRaises(ValueError):
            cc.custom_hmac(b"short", b"x")

    def test_check_function(self):
        self.assertTrue(cc.check_hmac_vectors()[0])

    def test_check_detects_standard_hmac(self):
        import hashlib
        import hmac as std     # tests only: simulate the classic mistake
        original = cc.custom_hmac
        try:
            cc.custom_hmac = lambda key, data: std.new(key, data, hashlib.sha256).digest()
            ok, msg = cc.check_hmac_vectors()
        finally:
            cc.custom_hmac = original
        self.assertFalse(ok)
        self.assertIn("incorrect", msg)

    def test_standard_value_really_is_standard_hmac(self):
        import hashlib
        import hmac as std
        self.assertEqual(std.new(KEY, b"hello world", hashlib.sha256).hexdigest(),
                         self.STANDARD)


class Base64Tests(unittest.TestCase):
    def test_standard_padded(self):
        self.assertEqual(cc.b64encode(KEY), KEY_B64)
        self.assertEqual(cc.b64decode(KEY_B64), KEY)

    def test_rejects_invalid(self):
        for bad in ["!!!", "AAEC AwQ=", "A"]:
            with self.assertRaises(ValueError):
                cc.b64decode(bad)


if __name__ == "__main__":
    unittest.main()
