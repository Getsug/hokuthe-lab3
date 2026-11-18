"""Crypto client: a Tkinter GUI client for the course crypto server.

Protocol, file formats and algorithms follow crypto_message_spec_v2.md.
"""

import base64
import hashlib
import json
import os
import re
import socket
import queue
import struct
import sys
import threading
import tkinter as tk
from dataclasses import dataclass
from tkinter import filedialog, messagebox, ttk
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --------------------------------------------------------------------------
# Constants (spec Sections 3, 4.1 and 8)
# --------------------------------------------------------------------------

DEFAULT_PORT = 8080
SOCKET_TIMEOUT = 30            # seconds; module-level so tests can override
MAX_HEADER_BYTES = 1000
MAX_PAYLOAD_BYTES = 1_048_576  # 1 MiB
AES_MAX_PLAINTEXT = 1_048_548  # 1 MiB - 28
HMAC_MAX_FILE = 1_048_576

USERNAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,32}")


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------

class ClientError(Exception):
    """Base class. The message is shown to the user and never holds key data."""


class ValidationError(ClientError):
    """Bad username/host/port, file too large, bad companion file."""


class FileAccessError(ClientError):
    """File read/write/permission failure."""


class NetworkError(ClientError):
    """Connect failure, timeout, reset, truncated reply."""


class ProtocolError(ClientError):
    """Reply violates the specification."""


class ServerError(ClientError):
    """The server answered with type "error"."""


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------

def validate_username(username):
    if not isinstance(username, str) or not USERNAME_RE.fullmatch(username):
        raise ValidationError(
            "Invalid username: use 1-32 characters from A-Z a-z 0-9 _ . -")
    return username


def validate_host(host):
    if not isinstance(host, str) or not host.strip():
        raise ValidationError("Host must not be empty.")
    if re.search(r"\s", host) or "/" in host or "://" in host:
        raise ValidationError(
            "Invalid host: enter a plain host name or IP address "
            "(no spaces or URL syntax).")
    return host


def validate_port(port):
    try:
        value = int(str(port).strip())
    except ValueError:
        raise ValidationError("Port must be a whole number from 1 to 65535.")
    if not 1 <= value <= 65535:
        raise ValidationError("Port must be a whole number from 1 to 65535.")
    return value


def validate_connection(host, port, username):
    """Validate all connection inputs; return (host, port_int, username)."""
    return validate_host(host), validate_port(port), validate_username(username)


def read_input_file(path, limit):
    """Read a file once in binary mode, enforcing the byte limit.

    At most limit + 1 bytes are read, so an oversized file is never loaded
    in full. The error for an oversized file names the file and its size.
    """
    name = os.path.basename(path) or str(path)
    try:
        with open(path, "rb") as f:
            data = f.read(limit + 1)
    except OSError as e:
        raise FileAccessError(f"Cannot read '{name}': {e.strerror or e}")
    if len(data) > limit:
        try:
            size = os.path.getsize(path)
        except OSError:
            size = len(data)
        raise ValidationError(
            f"File '{name}' is {size:,} bytes, which exceeds the "
            f"{limit:,}-byte limit.")
    return data


# --------------------------------------------------------------------------
# Framing (spec Section 3)
# --------------------------------------------------------------------------

def recv_exact(sock, n):
    """Read exactly n bytes from sock, looping over short reads."""
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except socket.timeout:
            raise NetworkError("The server did not respond in time (timeout).")
        except OSError as e:
            raise NetworkError(f"Network error while receiving: {e}")
        if not chunk:
            raise NetworkError("Connection closed before the full message arrived.")
        buf += chunk
    return bytes(buf)


def build_request(header, payload=b""):
    """Return the framed request: 4-byte big-endian length, JSON header, payload.

    payload_len is always set from the payload and placed last in the header.
    The header length is measured in UTF-8 bytes.
    """
    fields = {k: v for k, v in header.items() if k != "payload_len"}
    fields["payload_len"] = len(payload)
    header_bytes = json.dumps(fields, separators=(",", ":")).encode("utf-8")
    if len(header_bytes) > MAX_HEADER_BYTES:
        raise ValidationError("Request header exceeds the 1000-byte limit.")
    return struct.pack(">I", len(header_bytes)) + header_bytes + payload


# --------------------------------------------------------------------------
# Transport (spec Sections 2, 4 and 7): one connection per request
# --------------------------------------------------------------------------

def read_reply(sock):
    """Read and validate one framed reply; return (header_dict, payload)."""
    (header_len,) = struct.unpack(">I", recv_exact(sock, 4))
    if not 1 <= header_len <= MAX_HEADER_BYTES:
        raise ProtocolError(
            f"Invalid reply from server: header length {header_len} is out of range.")
    raw = recv_exact(sock, header_len)
    try:
        header = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ProtocolError("Invalid reply from server: header is not valid JSON.")
    if not isinstance(header, dict):
        raise ProtocolError("Invalid reply from server: header is not a JSON object.")
    payload_len = header.get("payload_len", 0)
    if (not isinstance(payload_len, int) or isinstance(payload_len, bool)
            or not 0 <= payload_len <= MAX_PAYLOAD_BYTES):
        raise ProtocolError("Invalid reply from server: bad payload length.")
    payload = recv_exact(sock, payload_len) if payload_len else b""
    return header, payload


def exchange(host, port, header, payload=b""):
    """Connect, send one request, read one reply, close. Returns (reply, payload)."""
    message = build_request(header, payload)
    try:
        with socket.create_connection((host, port), timeout=SOCKET_TIMEOUT) as sock:
            sock.settimeout(SOCKET_TIMEOUT)
            sock.sendall(message)
            return read_reply(sock)
    except socket.timeout:
        raise NetworkError("The server did not respond in time (timeout).")
    except OSError as e:
        raise NetworkError(f"Could not communicate with {host}:{port}: "
                           f"{e.strerror or e}")


def _expect(reply, expected_type):
    """Raise ServerError for type "error", ProtocolError for any other mismatch."""
    rtype = reply.get("type")
    if rtype == "error":
        detail = str(reply.get("detail", "unspecified error"))[:200]
        raise ServerError(f"Server returned an error: {detail}")
    if rtype != expected_type:
        raise ProtocolError(
            f"Unexpected reply from server (expected '{expected_type}').")


def request_key(host, port, username):
    """Fetch a new 32-byte key from the server."""
    reply, _ = exchange(host, port, {"type": "get_key", "username": username})
    _expect(reply, "key_result")
    try:
        key = b64decode(reply["key"])
    except (KeyError, TypeError, ValueError):
        raise ProtocolError("Invalid reply from server: bad key encoding.")
    if len(key) != 32:
        raise ProtocolError("Invalid reply from server: key is not 32 bytes.")
    return key


# --------------------------------------------------------------------------
# Crypto (spec Sections 5 and 6)
# --------------------------------------------------------------------------

def b64encode(data):
    """Standard base64 with padding, as text."""
    return base64.b64encode(data).decode("ascii")


def b64decode(text):
    """Strict standard-base64 decode; raises ValueError on invalid input."""
    return base64.b64decode(text, validate=True)


def aes_encrypt(key, plaintext, nonce=None):
    """Return nonce(12) | ciphertext | tag(16), with no AAD.

    A fresh random nonce is used unless one is given; the nonce argument
    exists only so the self-check can use the fixed test-vector nonce.
    """
    if nonce is None:
        nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def aes_decrypt(key, blob):
    """Inverse of aes_encrypt (used by the self-check and tests)."""
    return AESGCM(key).decrypt(blob[:12], blob[12:], None)


def sha256(data):
    return hashlib.sha256(data).digest()


def custom_hmac(key, data):
    """The course HMAC (spec Section 6). NOT standard HMAC / RFC 2104.

    Ki and Ko are the 32-byte key XORed with 0x36 / 0x5c, with no block
    padding: SHA-256(Ko || SHA-256(Ki || data)), the inner hash as raw bytes.
    """
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    ki = bytes(b ^ 0x36 for b in key)
    ko = bytes(b ^ 0x5C for b in key)
    return sha256(ko + sha256(ki + data))


def request_decrypt(host, port, username, key, blob):
    """Send an encrypted file to the server; return the decrypted bytes."""
    reply, payload = exchange(
        host, port,
        {"type": "decrypt", "username": username, "key": b64encode(key)}, blob)
    _expect(reply, "decrypt_result")
    return payload


def request_verify(host, port, username, key, mac, data):
    """Ask the server to verify an HMAC. Returns True for VERIFIED, False for FAILED.

    FAILED is a valid answer, not an error; only "error" replies raise.
    """
    reply, _ = exchange(
        host, port,
        {"type": "verify_hmac", "username": username,
         "key": b64encode(key), "hmac": b64encode(mac)}, data)
    _expect(reply, "verify_result")
    result = reply.get("result")
    if result not in ("VERIFIED", "FAILED"):
        raise ProtocolError("Invalid reply from server: unknown verification result.")
    return result == "VERIFIED"


# --------------------------------------------------------------------------
# File output
# --------------------------------------------------------------------------

def write_file(path, data):
    """Write bytes to path, converting OS errors to FileAccessError."""
    try:
        with open(path, "wb") as f:
            f.write(data)
    except OSError as e:
        raise FileAccessError(
            f"Cannot write '{os.path.basename(path)}': {e.strerror or e}")


def check_output_dir(out_dir):
    if not os.path.isdir(out_dir):
        raise FileAccessError(f"Output folder does not exist: {out_dir}")
    if not os.access(out_dir, os.W_OK):
        raise FileAccessError(f"Output folder is not writable: {out_dir}")


def decrypted_name(filename):
    """Insert "_decrypted" before the last extension: photo.jpg -> photo_decrypted.jpg.

    A name with no extension just gets the suffix (README -> README_decrypted).
    """
    stem, ext = os.path.splitext(filename)
    return f"{stem}_decrypted{ext}"


def aes_output_paths(in_path, out_dir):
    """Return (enc_path, key_path, decrypted_path).

    .enc and .key follow the spec's naming; the decrypted copy keeps the
    original extension: photo.jpg -> photo_decrypted.jpg.
    """
    name = os.path.basename(in_path)
    base = os.path.join(out_dir, name)
    return (base + ".enc", base + ".key",
            os.path.join(out_dir, decrypted_name(name)))


# --------------------------------------------------------------------------
# Workflows
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Connection:
    host: str
    port: int
    username: str


@dataclass
class AesResult:
    match: bool
    enc_path: str
    key_path: str
    decrypted_path: Optional[str]   # None unless the bytes matched


def aes_roundtrip(conn, key, in_path, out_dir):
    """Encrypt locally, have the server decrypt, compare with the original.

    The .enc and .key files are written before the network request; the
    decrypted copy (<name>_decrypted.<ext>) is written only after a
    byte-for-byte match.
    """
    plaintext = read_input_file(in_path, AES_MAX_PLAINTEXT)
    check_output_dir(out_dir)
    enc_path, key_path, dec_path = aes_output_paths(in_path, out_dir)
    blob = aes_encrypt(key, plaintext)
    write_file(enc_path, blob)
    write_file(key_path, b64encode(key).encode("ascii"))
    returned = request_decrypt(conn.host, conn.port, conn.username, key, blob)
    if returned != plaintext:
        return AesResult(False, enc_path, key_path, None)
    write_file(dec_path, returned)
    return AesResult(True, enc_path, key_path, dec_path)


@dataclass
class HmacResult:
    verified: bool
    hmac_path: Optional[str]   # None when verifying previously saved files
    key_path: Optional[str]


def hmac_output_paths(in_path, out_dir):
    """Return (hmac_path, hmackey_path) per the spec's naming."""
    base = os.path.join(out_dir, os.path.basename(in_path))
    return base + ".hmac", base + ".hmackey"


def default_companion_paths(in_path):
    """Spec-convention .hmac / .hmackey paths next to the input file."""
    return in_path + ".hmac", in_path + ".hmackey"


def hmac_compute_and_verify(conn, key, in_path, out_dir):
    """Compute the HMAC locally, save .hmac/.hmackey, then verify on the server."""
    data = read_input_file(in_path, HMAC_MAX_FILE)
    check_output_dir(out_dir)
    hmac_path, key_path = hmac_output_paths(in_path, out_dir)
    mac = custom_hmac(key, data)
    write_file(hmac_path, b64encode(mac).encode("ascii"))
    write_file(key_path, b64encode(key).encode("ascii"))
    verified = request_verify(conn.host, conn.port, conn.username, key, mac, data)
    return HmacResult(verified, hmac_path, key_path)


def _read_b32_file(path, what):
    """Read a base64-text companion file that must decode to exactly 32 bytes."""
    raw = read_input_file(path, 1024)
    name = os.path.basename(path)
    try:
        value = b64decode(raw.decode("ascii").strip())
    except (UnicodeDecodeError, ValueError):
        raise ValidationError(f"The {what} file '{name}' is not valid base64 text.")
    if len(value) != 32:
        raise ValidationError(
            f"The {what} file '{name}' must decode to exactly 32 bytes "
            f"(found {len(value)}).")
    return value


def hmac_verify_saved(conn, in_path, hmac_path, key_path):
    """Verify a file against previously saved .hmac and .hmackey files."""
    data = read_input_file(in_path, HMAC_MAX_FILE)
    mac = _read_b32_file(hmac_path, "HMAC")
    key = _read_b32_file(key_path, "key")
    verified = request_verify(conn.host, conn.port, conn.username, key, mac, data)
    return HmacResult(verified, None, None)


# --------------------------------------------------------------------------
# Self-checks (spec Section 9)
# --------------------------------------------------------------------------

HMAC_VECTOR_KEY = bytes(range(32))
HMAC_VECTOR_KI_HEX = "36373435323330313e3f3c3d3a3b383926272425222320212e2f2c2d2a2b2829"
HMAC_VECTOR_KO_HEX = "5c5d5e5f58595a5b54555657505152534c4d4e4f48494a4b4445464740414243"
HMAC_VECTOR_INNER_HEX = "05001c1f5260531db22d744e1629e7450903558c545cdd514bea3f555684deac"
HMAC_VECTOR_HELLO_HEX = "585c65e6deb8b876ed74222c5964060e707192df8ce9b91b6198de173fbfff2e"
HMAC_VECTOR_HELLO_B64 = "WFxl5t64uHbtdCIsWWQGDnBxkt+M6bkbYZjeFz+//y4="
HMAC_VECTOR_EMPTY_HEX = "bb7a30c41398c718904264ee91bc9ea48a36493f9e5a5577f53a1408a6ffa5b3"
# What a STANDARD HMAC-SHA256 would give for "hello world": wrong for this course.
STANDARD_HMAC_HELLO_HEX = "411b9a51e8565e1fc79643b2a6c4672f4a3c3e573c33d0995a08748cb6128e8e"


def check_hmac_vectors():
    """Return (ok, message) for the Section 9 HMAC vectors."""
    try:
        key = HMAC_VECTOR_KEY
        ki = bytes(b ^ 0x36 for b in key)
        ko = bytes(b ^ 0x5C for b in key)
        hello = custom_hmac(key, b"hello world")
        good = (
            ki.hex() == HMAC_VECTOR_KI_HEX
            and ko.hex() == HMAC_VECTOR_KO_HEX
            and sha256(ki + b"hello world").hex() == HMAC_VECTOR_INNER_HEX
            and hello.hex() == HMAC_VECTOR_HELLO_HEX
            and b64encode(hello) == HMAC_VECTOR_HELLO_B64
            and custom_hmac(key, b"").hex() == HMAC_VECTOR_EMPTY_HEX
            and hello.hex() != STANDARD_HMAC_HELLO_HEX
        )
    except Exception:
        good = False
    if not good:
        return False, ("The HMAC implementation is incorrect: it does not match "
                       "the specification's test vectors.")
    return True, "HMAC vectors OK."


AES_VECTOR_KEY = bytes(range(32))
AES_VECTOR_NONCE = bytes(range(12))
AES_VECTOR_PLAINTEXT = b"hello world"
AES_VECTOR_BLOB_HEX = (
    "000102030405060708090a0b2f67ba77aac5b574ff2df305301c56437e2377b9"
    "8ef3961c271928")


def check_aes_vector():
    """Return (ok, message) for the Section 9 AES-GCM vector."""
    try:
        blob = aes_encrypt(AES_VECTOR_KEY, AES_VECTOR_PLAINTEXT, AES_VECTOR_NONCE)
        if blob.hex() != AES_VECTOR_BLOB_HEX:
            raise ValueError("encrypted output differs")
        if aes_decrypt(AES_VECTOR_KEY, bytes.fromhex(AES_VECTOR_BLOB_HEX)) \
                != AES_VECTOR_PLAINTEXT:
            raise ValueError("decrypted output differs")
    except Exception:
        return False, ("The AES-GCM implementation is incorrect: it does not "
                       "match the specification's test vector.")
    return True, "AES-GCM vector OK."


FRAMING_VECTOR_HEX = (
    "000000397b2274797065223a226765745f6b6579222c22757365726e616d65223a"
    "2273747564656e743031222c227061796c6f61645f6c656e223a307d")


def check_framing_vector():
    """Return (ok, message) for the Section 9 get_key framing vector."""
    built = build_request({"type": "get_key", "username": "student01"})
    if built.hex() != FRAMING_VECTOR_HEX:
        return False, ("Message framing does not match the specification's "
                       "test vector; the framing implementation is incorrect.")
    return True, "Framing vector OK."


@dataclass
class SelfCheckStatus:
    framing_ok: bool
    aes_ok: bool
    hmac_ok: bool
    messages: list

    def enabled(self, workflow):
        """A workflow is usable only if framing and its own check passed."""
        own = self.aes_ok if workflow == "aes" else self.hmac_ok
        return self.framing_ok and own


def run_self_checks():
    """Run all startup self-checks and return a SelfCheckStatus."""
    f_ok, f_msg = check_framing_vector()
    a_ok, a_msg = check_aes_vector()
    h_ok, h_msg = check_hmac_vectors()
    return SelfCheckStatus(f_ok, a_ok, h_ok,
                           [m for ok, m in ((f_ok, f_msg), (a_ok, a_msg), (h_ok, h_msg))
                            if not ok])


# --------------------------------------------------------------------------
# Controller state
# --------------------------------------------------------------------------

class KeyHolder:
    """In-memory, single-use key for one workflow. Never displayed or logged."""

    def __init__(self):
        self._key = None

    def set(self, key):
        self._key = key

    def clear(self):
        self._key = None

    @property
    def loaded(self):
        return self._key is not None

    @property
    def key(self):
        return self._key

    def __repr__(self):
        return f"KeyHolder(loaded={self.loaded})"   # never expose key bytes


def planned_outputs(workflow, hmac_mode, in_path, out_dir):
    """Every path a run could write, so overwrites can be confirmed up front."""
    if workflow == "aes":
        return list(aes_output_paths(in_path, out_dir))
    if hmac_mode == "compute":
        return list(hmac_output_paths(in_path, out_dir))
    return []


# --------------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------------

class TkDialogs:
    """Modal dialogs; replaceable in tests."""

    def error(self, title, message):
        messagebox.showerror(title, message)

    def confirm(self, title, message):
        return messagebox.askyesno(title, message, icon="warning")


class App:
    """Main window and controller.

    Network and crypto work runs on a worker thread. The worker never touches
    Tk; it posts its outcome to a queue that the main thread polls.
    """

    POLL_MS = 50
    MIN_SIZE = (720, 640)

    def __init__(self, root, status=None, dialogs=None):
        self.root = root
        self.status = status if status is not None else run_self_checks()
        self.dialogs = dialogs if dialogs is not None else TkDialogs()
        self.keys = {"aes": KeyHolder(), "hmac": KeyHolder()}
        self.busy = False
        self._queue = queue.Queue()
        self._auto = {}          # field name -> last auto-filled value

        v = tk.StringVar
        self.host, self.port, self.username = v(), v(value=str(DEFAULT_PORT)), v()
        self.workflow, self.hmac_mode = v(value="aes"), v(value="compute")
        self.aes_in, self.aes_out = v(), v()
        self.hmac_in, self.hmac_out = v(), v()
        self.hmac_file, self.hmackey_file = v(), v()
        self.status_text, self.result_text = v(value="Ready."), v()
        self.key_text = {"aes": v(), "hmac": v()}

        self._build()
        self._wire()
        self.refresh_controls()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self._poll_id = self.root.after(self.POLL_MS, self._poll)
        if self.status.messages:
            self.root.after(100, self._show_self_check_failure)

    # -- construction ------------------------------------------------------

    def _build(self):
        root = self.root
        root.title("Crypto Client")
        root.minsize(*self.MIN_SIZE)
        style = ttk.Style(root)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        family = "Segoe UI" if sys.platform == "win32" else "TkDefaultFont"
        style.configure(".", font=(family, 10))
        style.configure("Title.TLabel", font=(family, 15, "bold"))
        style.configure("Ok.TLabel", foreground="#1b7f3b", font=(family, 11, "bold"))
        style.configure("Warn.TLabel", foreground="#a15c00", font=(family, 11, "bold"))
        style.configure("Err.TLabel", foreground="#b3261e", font=(family, 11, "bold"))
        style.configure("Start.TButton", font=(family, 11, "bold"), padding=(14, 6))

        main = ttk.Frame(root, padding=14)
        main.grid(sticky="nsew")
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        main.columnconfigure(0, weight=1)
        main.rowconfigure(7, weight=1)       # activity log grows
        self.main = main

        # row 0: self-check banner (hidden unless a check failed)
        self.banner = tk.Label(main, bg="#b3261e", fg="white", anchor="w",
                               justify="left", wraplength=660, padx=10, pady=6)
        self.banner.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        self.banner.grid_remove()

        ttk.Label(main, text="Crypto Client", style="Title.TLabel").grid(
            row=1, column=0, sticky="w", pady=(0, 8))

        # row 2: connection settings; row 3: workflow selector
        conn = ttk.LabelFrame(main, text="Server", padding=8)
        conn.grid(row=2, column=0, sticky="ew")
        conn.columnconfigure(1, weight=1)
        ttk.Label(conn, text="Host").grid(row=0, column=0, sticky="w")
        self.host_entry = ttk.Entry(conn, textvariable=self.host)
        self.host_entry.grid(row=0, column=1, sticky="ew", padx=(6, 12))
        ttk.Label(conn, text="Port").grid(row=0, column=2, sticky="w")
        self.port_entry = ttk.Entry(conn, textvariable=self.port, width=7)
        self.port_entry.grid(row=0, column=3, padx=(6, 0))
        ttk.Label(conn, text="Username").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.user_entry = ttk.Entry(conn, textvariable=self.username)
        self.user_entry.grid(row=1, column=1, sticky="ew", padx=(6, 12), pady=(6, 0))

        sel = ttk.Frame(main)
        sel.grid(row=3, column=0, sticky="w", pady=(10, 4))
        ttk.Label(sel, text="Operation").grid(row=0, column=0, padx=(0, 10))
        self.radio_aes = ttk.Radiobutton(sel, text="AES encrypt / decrypt", value="aes",
                                         variable=self.workflow)
        self.radio_hmac = ttk.Radiobutton(sel, text="HMAC verify", value="hmac",
                                          variable=self.workflow)
        self.radio_aes.grid(row=0, column=1, padx=(0, 12))
        self.radio_hmac.grid(row=0, column=2)

        # row 4: workflow panels share one grid cell
        panels = ttk.Frame(main)
        panels.grid(row=4, column=0, sticky="ew")
        panels.columnconfigure(0, weight=1)
        self.aes_panel = self._build_aes_panel(panels)
        self.hmac_panel = self._build_hmac_panel(panels)
        self.aes_panel.grid(row=0, column=0, sticky="ew")
        self.hmac_panel.grid(row=0, column=0, sticky="ew")

        # row 5: start button (label follows the selected workflow)
        self.start_btn = ttk.Button(main, text="Start Encrypting", style="Start.TButton",
                                    command=self.start)
        self.start_btn.grid(row=5, column=0, sticky="w", pady=(10, 4))

        # row 6: fixed-height progress area, status and result
        feedback = ttk.Frame(main)
        feedback.grid(row=6, column=0, sticky="ew")
        feedback.columnconfigure(0, weight=1)
        self.progress_area = tk.Frame(feedback, height=18)
        self.progress_area.grid(row=0, column=0, sticky="ew")
        self.progress_area.pack_propagate(False)       # height stays fixed
        self.progress = ttk.Progressbar(self.progress_area, mode="indeterminate")
        ttk.Label(feedback, textvariable=self.status_text).grid(
            row=1, column=0, sticky="w", pady=(4, 0))
        self.result_label = ttk.Label(feedback, textvariable=self.result_text,
                                      wraplength=660, justify="left")
        self.result_label.grid(row=2, column=0, sticky="w", pady=(2, 6))

        # row 7: read-only activity log
        log_frame = ttk.LabelFrame(main, text="Activity", padding=4)
        log_frame.grid(row=7, column=0, sticky="nsew")
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        mono = ("Consolas", 9) if sys.platform == "win32" else "TkFixedFont"
        self.log = tk.Text(log_frame, height=6, state="disabled", wrap="word",
                           borderwidth=0, font=mono)
        scroll = ttk.Scrollbar(log_frame, command=self.log.yview)
        self.log.configure(yscrollcommand=scroll.set)
        self.log.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")

    def _path_row(self, parent, row, label, var, browse):
        lab = ttk.Label(parent, text=label)
        entry = ttk.Entry(parent, textvariable=var)
        btn = ttk.Button(parent, text="Browse...", command=browse)
        lab.grid(row=row, column=0, sticky="w", pady=3)
        entry.grid(row=row, column=1, sticky="ew", padx=6, pady=3)
        btn.grid(row=row, column=2, pady=3)
        return [lab, entry, btn]

    def _build_aes_panel(self, parent):
        frame = ttk.LabelFrame(parent, text="AES-256-GCM", padding=8)
        frame.columnconfigure(1, weight=1)
        key_row = ttk.Frame(frame)
        key_row.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 4))
        self.aes_key_btn = ttk.Button(key_row, text="Get AES Key",
                                      command=lambda: self.get_key("aes"))
        self.aes_key_btn.grid(row=0, column=0)
        ttk.Label(key_row, textvariable=self.key_text["aes"]).grid(
            row=0, column=1, padx=10)
        rows = self._path_row(frame, 1, "Input file", self.aes_in,
                              lambda: self._browse_file(self.aes_in))
        rows += self._path_row(frame, 2, "Output folder", self.aes_out,
                               lambda: self._browse_dir(self.aes_out))
        self.aes_widgets = [self.aes_key_btn] + rows
        return frame

    def _build_hmac_panel(self, parent):
        frame = ttk.LabelFrame(parent, text="Course HMAC", padding=8)
        frame.columnconfigure(1, weight=1)
        mode_row = ttk.Frame(frame)
        mode_row.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 4))
        self.radio_compute = ttk.Radiobutton(
            mode_row, text="Compute & verify", value="compute", variable=self.hmac_mode)
        self.radio_saved = ttk.Radiobutton(
            mode_row, text="Verify saved files", value="saved", variable=self.hmac_mode)
        self.radio_compute.grid(row=0, column=0, padx=(0, 12))
        self.radio_saved.grid(row=0, column=1)

        self.hmac_key_row = ttk.Frame(frame)
        self.hmac_key_row.grid(row=1, column=0, columnspan=3, sticky="w", pady=(0, 4))
        self.hmac_key_btn = ttk.Button(self.hmac_key_row, text="Get HMAC Key",
                                       command=lambda: self.get_key("hmac"))
        self.hmac_key_btn.grid(row=0, column=0)
        ttk.Label(self.hmac_key_row, textvariable=self.key_text["hmac"]).grid(
            row=0, column=1, padx=10)

        in_row = self._path_row(frame, 2, "Input file", self.hmac_in,
                                lambda: self._browse_file(self.hmac_in))
        self.hmac_out_row = self._path_row(frame, 3, "Output folder", self.hmac_out,
                                           lambda: self._browse_dir(self.hmac_out))
        self.hmac_file_row = self._path_row(frame, 4, "HMAC file", self.hmac_file,
                                            lambda: self._browse_file(self.hmac_file))
        self.hmackey_row = self._path_row(frame, 5, "Key file", self.hmackey_file,
                                          lambda: self._browse_file(self.hmackey_file))
        self.hmac_widgets = ([self.hmac_key_btn, self.radio_compute, self.radio_saved]
                             + in_row + self.hmac_out_row + self.hmac_file_row
                             + self.hmackey_row)
        return frame

    def _wire(self):
        for var in (self.workflow, self.hmac_mode):
            var.trace_add("write", lambda *_: self.refresh_controls())
        self.aes_in.trace_add("write", lambda *_: self._autofill(
            self.aes_in, [("aes_out", self.aes_out, os.path.dirname)]))
        self.hmac_in.trace_add("write", lambda *_: self._autofill(
            self.hmac_in,
            [("hmac_out", self.hmac_out, os.path.dirname),
             ("hmac_file", self.hmac_file, lambda p: default_companion_paths(p)[0]),
             ("hmackey_file", self.hmackey_file,
              lambda p: default_companion_paths(p)[1])]))
        for var in (self.hmac_in, self.hmac_file, self.hmackey_file):
            var.trace_add("write", lambda *_: self.refresh_controls())

    # -- helpers -----------------------------------------------------------

    def _autofill(self, source, targets):
        """Fill derived fields unless the user has typed their own value."""
        path = source.get().strip()
        for name, var, derive in targets:
            current = var.get()
            if current == "" or current == self._auto.get(name):
                value = derive(path) if path else ""
                self._auto[name] = value
                var.set(value)

    def _browse_file(self, var):
        path = filedialog.askopenfilename()
        if path:
            var.set(os.path.normpath(path))

    def _browse_dir(self, var):
        path = filedialog.askdirectory()
        if path:
            var.set(os.path.normpath(path))

    def add_log(self, text):
        """Append a line to the activity log. Callers never pass key material."""
        self.log.configure(state="normal")
        self.log.insert("end", text + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def set_result(self, text, level):
        style = {"ok": "Ok.TLabel", "warn": "Warn.TLabel", "error": "Err.TLabel"}.get(
            level, "TLabel")
        self.result_label.configure(style=style)
        self.result_text.set(text)

    def _report_error(self, err):
        message = str(err) if isinstance(err, ClientError) else \
            f"Unexpected error ({type(err).__name__})."
        self.status_text.set("Failed.")
        self.set_result("Error: " + message, "error")
        self.add_log("Error: " + message)
        self.dialogs.error("Error", message)

    def _show_self_check_failure(self):
        self.banner.configure(text="Self-check failed. " + " ".join(self.status.messages))
        self.banner.grid()
        self.dialogs.error("Self-check failed", "\n\n".join(self.status.messages)
                           + "\n\nThe affected operation has been disabled.")

    @staticmethod
    def _set_widgets(widgets, enabled):
        for w in widgets:
            w.state(["!disabled"] if enabled else ["disabled"])

    def _ready_to_start(self):
        if self.workflow.get() == "aes":
            return self.keys["aes"].loaded
        if self.hmac_mode.get() == "compute":
            return self.keys["hmac"].loaded
        return all(v.get().strip() for v in
                   (self.hmac_in, self.hmac_file, self.hmackey_file))

    def refresh_controls(self):
        wf = self.workflow.get()
        saved = wf == "hmac" and self.hmac_mode.get() == "saved"
        usable = self.status.enabled(wf) and not self.busy

        # which panel / rows are visible
        if wf == "aes":
            self.hmac_panel.grid_remove()
            self.aes_panel.grid()
        else:
            self.aes_panel.grid_remove()
            self.hmac_panel.grid()
        compute_only = [self.hmac_key_row] + self.hmac_out_row
        saved_only = self.hmac_file_row + self.hmackey_row
        for w in compute_only:
            (w.grid_remove if saved else w.grid)()
        for w in saved_only:
            (w.grid if saved else w.grid_remove)()

        self.start_btn.configure(
            text="Start Encrypting" if wf == "aes" else "Start Verifying")
        self._set_widgets(self.aes_widgets, self.status.enabled("aes") and not self.busy)
        self._set_widgets(self.hmac_widgets, self.status.enabled("hmac") and not self.busy)
        self._set_widgets([self.start_btn], usable and self._ready_to_start())
        self._set_widgets([self.host_entry, self.port_entry, self.user_entry,
                           self.radio_aes, self.radio_hmac], not self.busy)
        for name in ("aes", "hmac"):
            if not self.status.enabled(name):
                self.key_text[name].set("Disabled (self-check failed)")
            else:
                self.key_text[name].set(
                    "Key loaded" if self.keys[name].loaded else "No key loaded")

    def set_busy(self, busy, message=""):
        self.busy = busy
        if busy:
            self.status_text.set(message)
            self.progress.pack(fill="x", pady=4)
            self.progress.start(12)
        else:
            self.progress.stop()
            self.progress.pack_forget()
        self.refresh_controls()

    # -- actions -----------------------------------------------------------

    def _connection(self):
        host, port, user = validate_connection(
            self.host.get().strip(), self.port.get(), self.username.get())
        return Connection(host, port, user)

    def get_key(self, workflow):
        if self.busy or not self.status.enabled(workflow):
            return
        try:
            conn = self._connection()
        except ClientError as e:
            self._report_error(e)
            return
        self.set_result("", "info")
        self.add_log("Requesting a new key...")
        self._run("key", workflow,
                  lambda: request_key(conn.host, conn.port, conn.username),
                  "Contacting server...")

    def start(self):
        wf = self.workflow.get()
        if self.busy or not self.status.enabled(wf):
            return
        try:
            conn = self._connection()
            job, label = (self._prepare_aes(conn) if wf == "aes"
                          else self._prepare_hmac(conn))
        except ClientError as e:
            self._report_error(e)
            return
        if job is None:               # user declined an overwrite
            self.status_text.set("Cancelled.")
            self.add_log("Cancelled: existing files were not overwritten.")
            return
        self.set_result("", "info")
        self._run(wf, wf, job, label)

    @staticmethod
    def _require_file(path, what, limit=None):
        if not path:
            raise ValidationError(f"Select the {what} first.")
        if not os.path.isfile(path):
            raise FileAccessError(f"The {what} does not exist: {path}")
        if limit is not None:
            size = os.path.getsize(path)
            if size > limit:
                raise ValidationError(
                    f"File '{os.path.basename(path)}' is {size:,} bytes, which "
                    f"exceeds the {limit:,}-byte limit.")

    def _confirm_overwrite(self, paths):
        existing = [p for p in paths if os.path.exists(p)]
        if not existing:
            return True
        names = "\n".join("  " + os.path.basename(p) for p in existing)
        return self.dialogs.confirm(
            "Overwrite files?",
            f"These files already exist and will be overwritten:\n\n{names}\n\nContinue?")

    @staticmethod
    def _output_dir(var, in_path):
        out_dir = var.get().strip() or os.path.dirname(in_path) or "."
        check_output_dir(out_dir)
        return out_dir

    def _prepare_aes(self, conn):
        in_path = self.aes_in.get().strip()
        self._require_file(in_path, "input file", AES_MAX_PLAINTEXT)
        out_dir = self._output_dir(self.aes_out, in_path)
        if not self._confirm_overwrite(planned_outputs("aes", None, in_path, out_dir)):
            return None, ""
        key = self.keys["aes"].key
        return (lambda: aes_roundtrip(conn, key, in_path, out_dir),
                "Encrypting and checking with the server...")

    def _prepare_hmac(self, conn):
        in_path = self.hmac_in.get().strip()
        self._require_file(in_path, "input file", HMAC_MAX_FILE)
        if self.hmac_mode.get() == "saved":
            hmac_path = self.hmac_file.get().strip()
            key_path = self.hmackey_file.get().strip()
            self._require_file(hmac_path, "HMAC file")
            self._require_file(key_path, "key file")
            return (lambda: hmac_verify_saved(conn, in_path, hmac_path, key_path),
                    "Verifying with the server...")
        out_dir = self._output_dir(self.hmac_out, in_path)
        if not self._confirm_overwrite(
                planned_outputs("hmac", "compute", in_path, out_dir)):
            return None, ""
        key = self.keys["hmac"].key
        return (lambda: hmac_compute_and_verify(conn, key, in_path, out_dir),
                "Computing HMAC and verifying with the server...")

    # -- background work ---------------------------------------------------

    def _run(self, kind, workflow, job, message):
        self.set_busy(True, message)

        def worker():
            try:
                outcome = job()
            except Exception as e:                  # reported on the main thread
                outcome = e
            self._queue.put((kind, workflow, outcome))

        threading.Thread(target=worker, daemon=True).start()

    def _poll(self):
        try:
            while True:
                self._finish(*self._queue.get_nowait())
        except queue.Empty:
            pass
        self._poll_id = self.root.after(self.POLL_MS, self._poll)

    def _finish(self, kind, workflow, outcome):
        self.set_busy(False)
        if isinstance(outcome, Exception):
            self._report_error(outcome)       # the key, if any, is kept for a retry
            return
        self.status_text.set("Done.")
        if kind == "key":
            self.keys[workflow].set(outcome)
            self.refresh_controls()
            self.set_result("New key loaded. You can now start.", "info")
            self.add_log("Key loaded.")
        elif kind == "aes":
            self._finish_aes(outcome)
        else:
            self._finish_hmac(outcome)

    def _finish_aes(self, res):
        self.keys["aes"].clear()                  # valid server reply: key is spent
        self.add_log(f"Saved {os.path.basename(res.enc_path)} and "
                     f"{os.path.basename(res.key_path)}.")
        if res.match:
            self.set_result("Match: the server's decrypted data is identical to "
                            "the original file.", "ok")
            self.add_log(f"Saved {os.path.basename(res.decrypted_path)}.")
        else:
            self.set_result("Mismatch: the decrypted data differs from the original "
                            "file. The decrypted file was not saved.", "warn")
            self.add_log("Mismatch: decrypted data differs from the original.")
        self.refresh_controls()

    def _finish_hmac(self, res):
        if res.hmac_path:
            self.keys["hmac"].clear()
            self.add_log(f"Saved {os.path.basename(res.hmac_path)} and "
                         f"{os.path.basename(res.key_path)}.")
        if res.verified:
            self.set_result("VERIFIED: the server confirms the HMAC matches the "
                            "file and key.", "ok")
            self.add_log("Server replied VERIFIED.")
        else:
            self.set_result("FAILED: the HMAC does not match the file and key. "
                            "(This is a valid verification result, not a "
                            "request error.)", "warn")
            self.add_log("Server replied FAILED.")
        self.refresh_controls()

    def on_close(self):
        if self.busy and not self.dialogs.confirm(
                "Operation in progress",
                "An operation is still running. Close the window anyway?"):
            return
        self.shutdown()

    def shutdown(self):
        """Cancel timers and destroy the window; a running worker is abandoned."""
        try:
            self.root.after_cancel(self._poll_id)
            self.progress.stop()
            self.root.destroy()
        except tk.TclError:
            pass


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
