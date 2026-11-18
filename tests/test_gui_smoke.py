"""GUI tests: build the real window and drive it against the mock server.

Skipped automatically when no display is available.
"""

import os
import sys
import tempfile
import time
import tkinter as tk
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import crypto_client as cc
from mock_server import MockServer


class FakeDialogs:
    def __init__(self, confirm_answer=True):
        self.errors = []
        self.confirms = []
        self.confirm_answer = confirm_answer

    def error(self, title, message):
        self.errors.append((title, message))

    def confirm(self, title, message):
        self.confirms.append((title, message))
        return self.confirm_answer


def good_status():
    return cc.SelfCheckStatus(True, True, True, [])


class GuiTestCase(unittest.TestCase):
    def setUp(self):
        try:
            self.root = tk.Tk()
        except tk.TclError:
            self.skipTest("no display available")
        self.root.withdraw()
        self.app = None
        self.addCleanup(self._destroy)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dialogs = FakeDialogs()
        self.srv = MockServer().start()
        self.addCleanup(self.srv.stop)

    def _destroy(self):
        if self.app is not None:
            self.app.shutdown()
        else:
            self.root.destroy()

    def make_app(self, status=None, dialogs=None):
        app = self.app = cc.App(self.root, status or good_status(), dialogs or self.dialogs)
        app.host.set("127.0.0.1")
        app.port.set(str(self.srv.port))
        app.username.set("student01")
        self.pump(0.15)
        return app

    def pump(self, seconds=0.0, until=None, timeout=10):
        end = time.time() + (timeout if until else seconds)
        while time.time() < end:
            self.root.update()
            if until and until():
                return True
            time.sleep(0.01)
        self.root.update()
        return until() if until else True

    def settle(self, app):
        self.assertTrue(self.pump(until=lambda: not app.busy), "operation did not finish")

    def make_file(self, name, data):
        p = os.path.join(self.tmp.name, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)
        return p

    def read(self, p):
        with open(p, "rb") as f:
            return f.read()

    @property
    def results(self):
        """The default output folder for files made in the temp dir."""
        return os.path.join(self.tmp.name, "results")

    def start_enabled(self, app):
        return "disabled" not in app.start_btn.state()


class AesGuiTests(GuiTestCase):
    def test_full_aes_run(self):
        app = self.make_app()
        src = self.make_file("note.txt", b"some secret text")
        self.assertFalse(self.start_enabled(app))             # no key yet
        self.assertEqual(app.start_btn.cget("text"), "Start Encrypting")

        app.get_key("aes")
        self.assertTrue(app.busy)
        self.settle(app)
        self.assertTrue(app.keys["aes"].loaded)
        self.assertEqual(app.key_text["aes"].get(), "Key loaded")
        self.assertTrue(self.start_enabled(app))

        app.aes_in.set(src)                          # output folder autofills
        self.assertEqual(app.aes_out.get(), self.results)
        self.assertFalse(os.path.exists(self.results))    # not created until Start
        app.start()
        self.settle(app)
        self.assertTrue(app.result_text.get().startswith("Match"), app.result_text.get())
        dec = os.path.join(self.results, "note_decrypted.txt")
        self.assertEqual(self.read(dec), b"some secret text")
        for name in ("note.txt.enc", "note.txt.key"):
            self.assertTrue(os.path.exists(os.path.join(self.results, name)), name)
        # nothing is written beside the input file
        self.assertEqual(sorted(os.listdir(self.tmp.name)), ["note.txt", "results"])
        self.assertFalse(app.keys["aes"].loaded)              # single-use
        self.assertFalse(self.start_enabled(app))
        self.assertEqual(self.dialogs.errors, [])

    def test_custom_output_folder_is_used_instead_of_results(self):
        app = self.make_app()
        src = self.make_file("note.txt", b"abc")
        other = os.path.join(self.tmp.name, "chosen")
        os.mkdir(other)
        app.get_key("aes"); self.settle(app)
        app.aes_in.set(src)
        app.aes_out.set(other)                                 # as if chosen with Browse
        app.start(); self.settle(app)
        self.assertTrue(app.result_text.get().startswith("Match"))
        self.assertEqual(sorted(os.listdir(other)),
                         ["note.txt.enc", "note.txt.key", "note_decrypted.txt"])
        self.assertFalse(os.path.exists(self.results))

    def test_missing_custom_folder_is_an_error_and_not_created(self):
        app = self.make_app()
        src = self.make_file("note.txt", b"abc")
        missing = os.path.join(self.tmp.name, "nope")
        app.get_key("aes"); self.settle(app)
        app.aes_in.set(src)
        app.aes_out.set(missing)
        app.start()
        self.assertFalse(app.busy)
        self.assertIn("does not exist", self.dialogs.errors[-1][1])
        self.assertFalse(os.path.exists(missing))
        self.assertTrue(app.keys["aes"].loaded)                # key kept for a retry

    def test_empty_output_field_falls_back_to_results(self):
        app = self.make_app()
        src = self.make_file("note.txt", b"abc")
        app.get_key("aes"); self.settle(app)
        app.aes_in.set(src)
        app.aes_out.set("")
        app.start(); self.settle(app)
        self.assertTrue(os.path.exists(os.path.join(self.results, "note.txt.enc")))

    def test_results_folder_not_created_when_input_is_rejected(self):
        app = self.make_app()
        big = self.make_file("big.bin", b"x" * (cc.AES_MAX_PLAINTEXT + 1))
        app.get_key("aes"); self.settle(app)
        app.aes_in.set(big)
        app.start()
        self.assertIn("big.bin", self.dialogs.errors[-1][1])
        self.assertFalse(os.path.exists(self.results))

    def test_results_folder_not_created_when_overwrite_declined(self):
        app = self.make_app(dialogs=FakeDialogs(confirm_answer=False))
        src = self.make_file("n.txt", b"abc")
        self.make_file(os.path.join("results", "n.txt.key"), b"old")
        app.get_key("aes"); self.settle(app)
        app.aes_in.set(src)
        app.start()
        self.assertEqual(os.listdir(self.results), ["n.txt.key"])  # nothing new written

    def test_mismatch_shown_and_not_saved(self):
        self.srv.behavior = "tamper_decrypt"
        app = self.make_app()
        src = self.make_file("n.txt", b"abc")
        app.get_key("aes"); self.settle(app)
        app.aes_in.set(src)
        app.start(); self.settle(app)
        self.assertTrue(app.result_text.get().startswith("Mismatch"))
        self.assertFalse(os.path.exists(os.path.join(self.results, "n_decrypted.txt")))

    def test_overwrite_declined_cancels_before_network(self):
        app = self.make_app(dialogs=FakeDialogs(confirm_answer=False))
        self.dialogs = app.dialogs
        src = self.make_file("n.txt", b"abc")
        self.make_file(os.path.join("results", "n.txt.enc"), b"old")
        app.get_key("aes"); self.settle(app)
        app.aes_in.set(src)
        app.start()
        self.assertFalse(app.busy)
        self.assertEqual(len(self.dialogs.confirms), 1)
        self.assertEqual(self.read(os.path.join(self.results, "n.txt.enc")), b"old")  # untouched
        self.assertTrue(app.keys["aes"].loaded)               # key kept

    def test_overwrite_accepted(self):
        app = self.make_app()
        src = self.make_file("n.txt", b"abc")
        self.make_file(os.path.join("results", "n.txt.enc"), b"old")
        app.get_key("aes"); self.settle(app)
        app.aes_in.set(src)
        app.start(); self.settle(app)
        self.assertEqual(len(self.dialogs.confirms), 1)
        self.assertNotEqual(self.read(os.path.join(self.results, "n.txt.enc")), b"old")

    def test_invalid_username_rejected_without_contacting_server(self):
        app = self.make_app()
        app.username.set("bad name")
        app.get_key("aes")
        self.assertFalse(app.busy)
        self.assertEqual(len(self.dialogs.errors), 1)
        self.assertIn("username", self.dialogs.errors[0][1].lower())

    def test_server_error_keeps_key_and_shows_error(self):
        self.srv.behavior = "always_error"
        app = self.make_app()
        app.get_key("aes"); self.settle(app)
        self.assertFalse(app.keys["aes"].loaded)
        self.assertTrue(app.result_text.get().startswith("Error"))
        self.assertEqual(len(self.dialogs.errors), 1)

    def test_error_on_run_retains_key(self):
        app = self.make_app()
        src = self.make_file("n.txt", b"abc")
        app.get_key("aes"); self.settle(app)
        app.aes_in.set(src)
        self.srv.behavior = "drop_connection"
        app.start(); self.settle(app)
        self.assertTrue(app.keys["aes"].loaded)
        self.assertTrue(app.result_text.get().startswith("Error"))

    def test_missing_and_oversized_input(self):
        app = self.make_app()
        app.get_key("aes"); self.settle(app)
        app.start()
        self.assertIn("Select", self.dialogs.errors[-1][1])
        big = self.make_file("big.bin", b"x" * (cc.AES_MAX_PLAINTEXT + 1))
        app.aes_in.set(big)
        app.start()
        self.assertIn("big.bin", self.dialogs.errors[-1][1])
        self.assertFalse(app.busy)


class HmacGuiTests(GuiTestCase):
    def switch_to_hmac(self, app):
        app.workflow.set("hmac")
        self.pump(0.05)

    def test_compute_and_verify_then_verify_saved(self):
        app = self.make_app()
        self.switch_to_hmac(app)
        self.assertEqual(app.start_btn.cget("text"), "Start Verifying")
        src = self.make_file("doc.txt", b"hello world")
        app.get_key("hmac"); self.settle(app)
        app.hmac_in.set(src)
        app.start(); self.settle(app)
        self.assertTrue(app.result_text.get().startswith("VERIFIED"))
        hmac_p = os.path.join(self.results, "doc.txt.hmac")
        key_p = os.path.join(self.results, "doc.txt.hmackey")
        self.assertTrue(os.path.exists(hmac_p) and os.path.exists(key_p))
        self.assertFalse(os.path.exists(src + ".hmac"))       # not beside the input
        self.assertFalse(app.keys["hmac"].loaded)

        app.hmac_mode.set("saved")
        self.pump(0.05)
        self.assertEqual(app.hmac_file.get(), hmac_p)             # found in results
        self.assertEqual(app.hmackey_file.get(), key_p)
        self.assertTrue(self.start_enabled(app))                  # no key needed
        app.start(); self.settle(app)
        self.assertTrue(app.result_text.get().startswith("VERIFIED"))

        with open(src, "wb") as f:                                # tamper
            f.write(b"hello worle")
        app.start(); self.settle(app)
        self.assertTrue(app.result_text.get().startswith("FAILED"))
        self.assertEqual(self.dialogs.errors, [])   # FAILED is not an error dialog

    def test_hmac_output_defaults_to_results_and_can_be_changed(self):
        app = self.make_app()
        self.switch_to_hmac(app)
        src = self.make_file("doc.txt", b"hello world")
        app.hmac_in.set(src)
        self.assertEqual(app.hmac_out.get(), self.results)
        other = os.path.join(self.tmp.name, "chosen")
        os.mkdir(other)
        app.hmac_out.set(other)
        app.get_key("hmac"); self.settle(app)
        app.start(); self.settle(app)
        self.assertTrue(app.result_text.get().startswith("VERIFIED"))
        self.assertEqual(sorted(os.listdir(other)), ["doc.txt.hmac", "doc.txt.hmackey"])
        self.assertFalse(os.path.exists(self.results))

    def test_saved_mode_falls_back_to_files_beside_input(self):
        app = self.make_app()
        self.switch_to_hmac(app)
        src = self.make_file("doc.txt", b"hello world")
        app.hmac_mode.set("saved")
        app.hmac_in.set(src)
        self.assertEqual(app.hmac_file.get(), src + ".hmac")       # nothing in results
        self.assertEqual(app.hmackey_file.get(), src + ".hmackey")

    def test_failed_and_error_use_different_styles(self):
        app = self.make_app()
        app.set_result("FAILED", "warn")
        warn = str(app.result_label.cget("style"))
        app.set_result("Error", "error")
        self.assertNotEqual(warn, str(app.result_label.cget("style")))

    def test_saved_mode_rejects_bad_companion(self):
        app = self.make_app()
        self.switch_to_hmac(app)
        src = self.make_file("d.txt", b"x")
        self.make_file("d.txt.hmac", b"not base64!!")
        self.make_file("d.txt.hmackey", b"also bad")
        app.hmac_mode.set("saved")
        app.hmac_in.set(src)
        app.start(); self.settle(app)
        self.assertTrue(app.result_text.get().startswith("Error"))

    def test_mode_toggle_shows_relevant_rows(self):
        app = self.make_app()
        self.switch_to_hmac(app)
        self.root.deiconify(); self.pump(0.2)
        self.assertTrue(app.hmac_key_row.winfo_ismapped())
        self.assertFalse(app.hmac_file_row[1].winfo_ismapped())
        app.hmac_mode.set("saved"); self.pump(0.1)
        self.assertFalse(app.hmac_key_row.winfo_ismapped())
        self.assertTrue(app.hmac_file_row[1].winfo_ismapped())


class LayoutAndGatingTests(GuiTestCase):
    def test_progress_does_not_shift_layout(self):
        app = self.make_app()
        self.root.deiconify(); self.pump(0.2)
        before = (app.result_label.winfo_y(), app.log.winfo_y(), app.progress_area.winfo_height())
        app.set_busy(True, "working")
        self.pump(0.1)
        during = (app.result_label.winfo_y(), app.log.winfo_y(), app.progress_area.winfo_height())
        app.set_busy(False)
        self.pump(0.1)
        after = (app.result_label.winfo_y(), app.log.winfo_y(), app.progress_area.winfo_height())
        self.assertEqual(before, during)
        self.assertEqual(before, after)

    def test_controls_disabled_while_busy(self):
        app = self.make_app()
        app.set_busy(True, "working")
        self.assertIn("disabled", app.aes_key_btn.state())
        self.assertIn("disabled", app.start_btn.state())
        self.assertIn("disabled", app.host_entry.state())
        app.set_busy(False)
        self.assertNotIn("disabled", app.aes_key_btn.state())

    def test_aes_selfcheck_failure_disables_only_aes(self):
        status = cc.SelfCheckStatus(True, False, True, ["AES-GCM implementation is incorrect"])
        app = self.make_app(status=status)
        self.pump(0.3)
        self.assertEqual(len(self.dialogs.errors), 1)             # error dialog shown
        self.assertIn("incorrect", app.banner.cget("text"))
        self.assertIn("disabled", app.aes_key_btn.state())
        self.assertIn("disabled", app.start_btn.state())
        app.get_key("aes")                                         # gate holds
        self.assertFalse(app.busy)
        app.workflow.set("hmac"); self.pump(0.05)
        self.assertNotIn("disabled", app.hmac_key_btn.state())     # HMAC unaffected

    def test_hmac_selfcheck_failure_disables_hmac(self):
        status = cc.SelfCheckStatus(True, True, False, ["HMAC implementation is incorrect"])
        app = self.make_app(status=status)
        app.workflow.set("hmac"); self.pump(0.3)
        self.assertIn("disabled", app.hmac_key_btn.state())
        self.assertIn("disabled", app.start_btn.state())
        self.assertNotIn("disabled", app.aes_key_btn.state())

    def test_framing_failure_disables_both(self):
        app = self.make_app(status=cc.SelfCheckStatus(False, True, True, ["framing"]))
        self.assertFalse(app.status.enabled("aes"))
        self.assertFalse(app.status.enabled("hmac"))

    def test_close_while_busy_asks_confirmation(self):
        dialogs = FakeDialogs(confirm_answer=False)
        app = self.make_app(dialogs=dialogs)
        app.set_busy(True, "working")
        app.on_close()
        self.assertEqual(len(dialogs.confirms), 1)
        self.assertTrue(self.root.winfo_exists())                  # not destroyed

    def test_log_never_contains_key(self):
        app = self.make_app()
        app.get_key("aes"); self.settle(app)
        key_b64 = cc.b64encode(app.keys["aes"].key)
        self.assertNotIn(key_b64, app.log.get("1.0", "end"))
        self.assertNotIn(key_b64, app.result_text.get())
        self.assertNotIn(key_b64, repr(app.keys["aes"]))

    def test_settings_not_persisted(self):
        before = set(os.listdir(os.path.dirname(os.path.abspath(cc.__file__))))
        self.make_app()
        after = set(os.listdir(os.path.dirname(os.path.abspath(cc.__file__))))
        self.assertEqual(before, after)


class SelfCheckFunctionTests(unittest.TestCase):
    def test_run_self_checks_all_pass(self):
        status = cc.run_self_checks()
        self.assertTrue(status.enabled("aes") and status.enabled("hmac"))
        self.assertEqual(status.messages, [])


if __name__ == "__main__":
    unittest.main()
