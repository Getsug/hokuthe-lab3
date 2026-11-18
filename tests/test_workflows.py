import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import crypto_client as cc
from mock_server import MockServer


class WorkflowTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name

    def make(self, name, data):
        p = os.path.join(self.dir, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)
        return p

    def read(self, path):
        with open(path, "rb") as f:
            return f.read()

    def conn(self, srv, user="student01"):
        return cc.Connection("127.0.0.1", srv.port, user)


class DecryptedNameTests(unittest.TestCase):
    def test_extension_preserved(self):
        cases = {
            "photo.jpg": "photo_decrypted.jpg",
            "report.txt": "report_decrypted.txt",
            "archive.tar.gz": "archive.tar_decrypted.gz",   # last extension only
            "README": "README_decrypted",                    # no extension
            ".bashrc": ".bashrc_decrypted",                  # dotfile, no extension
            "a.b.c.d": "a.b.c_decrypted.d",
            "photo_decrypted.jpg": "photo_decrypted_decrypted.jpg",
        }
        for name, expected in cases.items():
            with self.subTest(name):
                self.assertEqual(cc.decrypted_name(name), expected)

    def test_overwrite_check_covers_decrypted_copy(self):
        paths = cc.planned_outputs("aes", None, os.path.join("in", "photo.jpg"), "out")
        self.assertIn(os.path.join("out", "photo_decrypted.jpg"), paths)

    def test_output_paths(self):
        enc, key, dec = cc.aes_output_paths(os.path.join("in", "photo.jpg"), "out")
        self.assertEqual(enc, os.path.join("out", "photo.jpg.enc"))
        self.assertEqual(key, os.path.join("out", "photo.jpg.key"))
        self.assertEqual(dec, os.path.join("out", "photo_decrypted.jpg"))


class ResultsFolderTests(WorkflowTestCase):
    def test_default_output_dir_is_results_beside_input(self):
        src = os.path.join(self.dir, "sub", "photo.jpg")
        self.assertEqual(cc.default_output_dir(src),
                         os.path.join(os.path.abspath(self.dir), "sub", "results"))

    def test_default_output_dir_for_relative_path(self):
        self.assertEqual(cc.default_output_dir("photo.jpg"),
                         os.path.join(os.path.abspath("."), "results"))

    def test_default_folder_is_created_on_demand(self):
        src = self.make("a.txt", b"x")
        target = cc.default_output_dir(src)
        self.assertFalse(os.path.exists(target))
        self.assertEqual(cc.prepare_output_dir(target, src), target)
        self.assertTrue(os.path.isdir(target))
        cc.prepare_output_dir(target, src)          # already there: fine

    def test_default_folder_check_ignores_path_spelling(self):
        src = self.make("a.txt", b"x")
        spelled = os.path.join(self.dir, ".", "results", "")
        cc.prepare_output_dir(spelled, src)
        self.assertTrue(os.path.isdir(os.path.join(self.dir, "results")))

    def test_other_folders_are_not_created(self):
        src = self.make("a.txt", b"x")
        other = os.path.join(self.dir, "elsewhere")
        with self.assertRaises(cc.FileAccessError):
            cc.prepare_output_dir(other, src)
        self.assertFalse(os.path.exists(other))

    def test_existing_custom_folder_is_accepted(self):
        src = self.make("a.txt", b"x")
        other = os.path.join(self.dir, "elsewhere")
        os.mkdir(other)
        self.assertEqual(cc.prepare_output_dir(other, src), other)

    def test_cannot_create_results_when_blocked_by_a_file(self):
        src = self.make("a.txt", b"x")
        self.make("results", b"i am a file, not a folder")
        with self.assertRaises(cc.FileAccessError):
            cc.prepare_output_dir(cc.default_output_dir(src), src)

    def test_companions_prefer_results_then_fall_back_beside_input(self):
        src = self.make("doc.txt", b"x")
        # nothing saved yet: spec convention (beside the input file)
        self.assertEqual(cc.default_companion_paths(src),
                         (src + ".hmac", src + ".hmackey"))
        # saved by this app: found in the results folder
        self.make(os.path.join("results", "doc.txt.hmac"), b"m")
        self.make(os.path.join("results", "doc.txt.hmackey"), b"k")
        res = cc.default_output_dir(src)
        self.assertEqual(cc.default_companion_paths(src),
                         (os.path.join(res, "doc.txt.hmac"),
                          os.path.join(res, "doc.txt.hmackey")))

    def test_companions_chosen_independently(self):
        src = self.make("doc.txt", b"x")
        self.make(os.path.join("results", "doc.txt.hmac"), b"m")
        self.make("doc.txt.hmackey", b"k")             # key only beside the input
        res = cc.default_output_dir(src)
        self.assertEqual(cc.default_companion_paths(src),
                         (os.path.join(res, "doc.txt.hmac"), src + ".hmackey"))

    def test_workflow_writes_into_created_results_folder(self):
        src = self.make("photo.jpg", b"pixels")
        out = cc.prepare_output_dir(cc.default_output_dir(src), src)
        with MockServer() as srv:
            key = cc.request_key("127.0.0.1", srv.port, "student01")
            res = cc.aes_roundtrip(self.conn(srv), key, src, out)
        self.assertTrue(res.match)
        self.assertEqual(sorted(os.listdir(out)),
                         ["photo.jpg.enc", "photo.jpg.key", "photo_decrypted.jpg"])


class AesRoundtripTests(WorkflowTestCase):
    def roundtrip(self, data, name="report.txt", behavior="normal"):
        src = self.make(name, data)
        out = os.path.join(self.dir, "out")
        os.mkdir(out)
        with MockServer(behavior=behavior) as srv:
            key = cc.request_key("127.0.0.1", srv.port, "student01")
            return key, src, out, cc.aes_roundtrip(self.conn(srv), key, src, out)

    def test_match_saves_all_files(self):
        data = os.urandom(5000)
        key, src, out, result = self.roundtrip(data)
        self.assertTrue(result.match)
        self.assertEqual(result.enc_path, os.path.join(out, "report.txt.enc"))
        self.assertEqual(self.read(result.decrypted_path), data)
        self.assertEqual(os.path.basename(result.decrypted_path), "report_decrypted.txt")
        # .enc is nonce|ciphertext|tag and decrypts locally with the saved key
        saved_key = cc.b64decode(self.read(result.key_path).decode())
        self.assertEqual(saved_key, key)
        self.assertEqual(cc.aes_decrypt(saved_key, self.read(result.enc_path)), data)
        self.assertEqual(len(self.read(result.enc_path)), len(data) + 28)
        # key file is base64 text with no trailing newline
        self.assertEqual(self.read(result.key_path), cc.b64encode(key).encode())
        # original untouched
        self.assertEqual(self.read(src), data)

    def test_empty_file(self):
        _, _, _, result = self.roundtrip(b"")
        self.assertTrue(result.match)
        self.assertEqual(self.read(result.decrypted_path), b"")

    def test_largest_file(self):
        _, _, _, result = self.roundtrip(os.urandom(cc.AES_MAX_PLAINTEXT))
        self.assertTrue(result.match)

    def test_mismatch_does_not_save_decrypted(self):
        _, _, out, result = self.roundtrip(b"hello world", behavior="tamper_decrypt")
        self.assertFalse(result.match)
        self.assertIsNone(result.decrypted_path)
        self.assertTrue(os.path.exists(result.enc_path))
        self.assertTrue(os.path.exists(result.key_path))
        self.assertFalse(os.path.exists(os.path.join(out, "report_decrypted.txt")))

    def test_too_large_refused_before_connecting(self):
        src = self.make("big.bin", b"x" * (cc.AES_MAX_PLAINTEXT + 1))
        conn = cc.Connection("127.0.0.1", 1, "u")   # nothing listens: must not connect
        with self.assertRaises(cc.ValidationError) as cm:
            cc.aes_roundtrip(conn, b"k" * 32, src, self.dir)
        self.assertIn("big.bin", str(cm.exception))

    def test_bad_output_folder(self):
        src = self.make("a.txt", b"x")
        conn = cc.Connection("127.0.0.1", 1, "u")
        with self.assertRaises(cc.FileAccessError):
            cc.aes_roundtrip(conn, b"k" * 32, src, os.path.join(self.dir, "missing"))

    def test_wrong_key_is_server_error(self):
        src = self.make("a.txt", b"data")
        with MockServer() as srv:
            blob = cc.aes_encrypt(b"a" * 32, b"data")
            with self.assertRaises(cc.ServerError):
                cc.request_decrypt("127.0.0.1", srv.port, "u", b"b" * 32, blob)

    def test_spec_vector_decrypts_on_server(self):
        with MockServer() as srv:
            data = cc.request_decrypt("127.0.0.1", srv.port, "u", cc.AES_VECTOR_KEY,
                                      bytes.fromhex(cc.AES_VECTOR_BLOB_HEX))
        self.assertEqual(data, b"hello world")


class HmacWorkflowTests(WorkflowTestCase):
    def setUp(self):
        super().setUp()
        self.out = os.path.join(self.dir, "out")
        os.mkdir(self.out)

    def test_compute_and_verify(self):
        data = os.urandom(3000)
        src = self.make("doc.bin", data)
        with MockServer() as srv:
            key = cc.request_key("127.0.0.1", srv.port, "student01")
            res = cc.hmac_compute_and_verify(self.conn(srv), key, src, self.out)
        self.assertTrue(res.verified)
        self.assertEqual(res.hmac_path, os.path.join(self.out, "doc.bin.hmac"))
        self.assertEqual(res.key_path, os.path.join(self.out, "doc.bin.hmackey"))
        self.assertEqual(self.read(res.hmac_path),
                         cc.b64encode(cc.custom_hmac(key, data)).encode())
        self.assertEqual(self.read(res.key_path), cc.b64encode(key).encode())

    def test_spec_example_verified_then_failed(self):
        with MockServer() as srv:
            mac = cc.custom_hmac(cc.HMAC_VECTOR_KEY, b"hello world")
            ok = cc.request_verify("127.0.0.1", srv.port, "u",
                                   cc.HMAC_VECTOR_KEY, mac, b"hello world")
            bad = cc.request_verify("127.0.0.1", srv.port, "u",
                                    cc.HMAC_VECTOR_KEY, mac, b"hello worle")
        self.assertTrue(ok)
        self.assertFalse(bad)      # FAILED is a normal result, not an exception

    def test_empty_file(self):
        src = self.make("empty", b"")
        with MockServer() as srv:
            key = cc.request_key("127.0.0.1", srv.port, "u")
            res = cc.hmac_compute_and_verify(self.conn(srv), key, src, self.out)
            self.assertTrue(res.verified)

    def test_largest_file(self):
        src = self.make("big", os.urandom(cc.HMAC_MAX_FILE))
        with MockServer() as srv:
            key = cc.request_key("127.0.0.1", srv.port, "u")
            res = cc.hmac_compute_and_verify(self.conn(srv), key, src, self.out)
            self.assertTrue(res.verified)

    def test_too_large_refused_before_connecting(self):
        src = self.make("huge", b"x" * (cc.HMAC_MAX_FILE + 1))
        with self.assertRaises(cc.ValidationError) as cm:
            cc.hmac_compute_and_verify(cc.Connection("127.0.0.1", 1, "u"),
                                       b"k" * 32, src, self.out)
        self.assertIn("huge", str(cm.exception))

    def test_malformed_request_is_server_error(self):
        with MockServer() as srv:
            with self.assertRaises(cc.ServerError):
                cc.request_verify("127.0.0.1", srv.port, "u", b"short", b"x" * 32, b"d")

    def test_verify_saved_then_tamper(self):
        src = self.make("doc.txt", b"original content")
        with MockServer() as srv:
            key = cc.request_key("127.0.0.1", srv.port, "u")
            cc.hmac_compute_and_verify(self.conn(srv), key, src, self.dir)
            hmac_p, key_p = cc.default_companion_paths(src)
            self.assertTrue(os.path.exists(hmac_p) and os.path.exists(key_p))
            self.assertTrue(cc.hmac_verify_saved(self.conn(srv), src, hmac_p, key_p).verified)
            with open(src, "wb") as f:
                f.write(b"0riginal content")
            self.assertFalse(cc.hmac_verify_saved(self.conn(srv), src, hmac_p, key_p).verified)

    def test_verify_saved_tolerates_whitespace(self):
        src = self.make("d", b"hello world")
        hp = self.make("d.hmac", cc.HMAC_VECTOR_HELLO_B64.encode() + b"\r\n")
        kp = self.make("d.hmackey",
                       b"  " + cc.b64encode(cc.HMAC_VECTOR_KEY).encode() + b"\n")
        with MockServer() as srv:
            self.assertTrue(cc.hmac_verify_saved(self.conn(srv), src, hp, kp).verified)

    def test_verify_saved_rejects_bad_companions(self):
        src = self.make("d", b"hello world")
        good_key = self.make("good.key", cc.b64encode(cc.HMAC_VECTOR_KEY).encode())
        conn = cc.Connection("127.0.0.1", 1, "u")    # must not connect
        cases = {
            "not base64": b"!!!notbase64!!!",
            "wrong length": cc.b64encode(b"short").encode(),
            "binary": b"\xff\xfe\x00",
            "empty": b"",
        }
        for name, content in cases.items():
            with self.subTest(name):
                bad = self.make("bad.hmac", content)
                with self.assertRaises(cc.ValidationError):
                    cc.hmac_verify_saved(conn, src, bad, good_key)
                with self.assertRaises(cc.ValidationError):
                    cc.hmac_verify_saved(conn, src, good_key, bad)

    def test_verify_saved_missing_file(self):
        src = self.make("d", b"x")
        with self.assertRaises(cc.FileAccessError):
            cc.hmac_verify_saved(cc.Connection("127.0.0.1", 1, "u"), src,
                                 os.path.join(self.dir, "none.hmac"),
                                 os.path.join(self.dir, "none.hmackey"))


if __name__ == "__main__":
    unittest.main()
