# Crypto Client — Design (v1)

Implements `requirements_v2.md` against `crypto_message_spec_v2.md`. Requirement IDs (R1–R40) are referenced in brackets. Protocol details are defined in the spec and are not repeated here.

## 1. Files

```
crypto_client.py        application: validation, framing, transport, crypto, workflows, self-checks, GUI
mock_server.py          local fake server (independent HMAC implementation)
requirements.txt        cryptography>=<min version, verified on Python 3.14 at creation>
README.md
tests/
  test_validation.py    username/host/port, size limits
  test_framing.py       framing vector, recv_exact, reply validation
  test_crypto.py        AES and HMAC vectors, standard-HMAC negative check
  test_workflows.py     both workflows end to end against the mock server, plus decrypted-file naming and the output-folder rules
  test_mock_server.py   mock server's own HMAC vs Section 9 vectors, fault modes
  test_gui_smoke.py     builds the window, skipped if no display
```

`crypto_client.py` is importable without starting the GUI, because the GUI starts only under `if __name__ == "__main__":`. This lets the tests import the logic directly [R39].

## 2. Layered architecture (inside `crypto_client.py`)

```
GUI (view + controller)       Tk widgets, state, background thread plumbing
      |
Workflows                     aes_roundtrip(), hmac_compute_and_verify(), hmac_verify_saved()
      |
Transport / Protocol          exchange(), build_request(), read_reply(), recv_exact()
      |
Crypto / Validation / IO      aes_encrypt(), custom_hmac(), validate_*(), read_input_file(), save_*()
```

Lower layers never import Tk. Workflows are plain functions that return a result object or raise `ClientError`, so they can be tested without a GUI.

### 2.1 Errors

```
ClientError(Exception)          base class, carries a user-facing message
  ValidationError               bad username/host/port, file too large, bad companion file
  FileAccessError               read/write/permission failures
  NetworkError                  connect, timeout, reset, truncated reply
  ProtocolError                 reply violates the spec (bad header, wrong type, bad base64)
  ServerError                   server sent type "error" (detail text is shown)
```

Each message states what failed and never contains key material [R13, R23].

### 2.2 Validation [R9–R13]

- `validate_username(s)` uses the regex `^[A-Za-z0-9_.-]{1,32}$` with `fullmatch`. A trailing newline is rejected.
- `validate_host(s)` requires non-empty text with no whitespace, no `/`, and no `://`.
- `validate_port(s)` requires an integer from 1 to 65535.
- `validate_connection(host, port, username)` calls all three and is run before every network call, including Get Key.
- `read_input_file(path, limit)` reads at most `limit + 1` bytes in binary mode, so a huge file is never fully loaded. If more than `limit` bytes come back, it raises `ValidationError` naming the file and its actual size via `os.path.getsize`. The limits are `AES_MAX_PLAINTEXT = 1_048_548` and `HMAC_MAX_FILE = 1_048_576`.
- Empty files are accepted.

### 2.3 Transport and protocol [R5–R8]

- `recv_exact(sock, n)` loops until `n` bytes arrive and raises `NetworkError` if the connection closes early.
- `build_request(header: dict, payload: bytes) -> bytes` sets `payload_len`, serializes JSON compactly (`separators=(",",":")`) in the order `type`, `username`, extras, `payload_len`, and prepends the 4-byte big-endian length (`struct.pack(">I", ...)`). The header is measured in UTF-8 bytes, not characters.
- `exchange(host, port, header, payload)` opens one connection with `socket.create_connection(timeout=30)` and keeps a 30-second timeout on every read. It sends the request, reads one reply, closes, and returns `(reply_dict, payload_bytes)`. Timeouts, resets and refused connections are converted to `NetworkError`.
- `read_reply(sock)` validates the reply as follows:
  - the reply header length is between 1 and 1000;
  - the header is valid UTF-8 JSON and a JSON object;
  - `payload_len` is an integer from 0 to 1 MiB.

  Anything else raises `ProtocolError`. Truncation raises `NetworkError`.
- Typed wrappers each check the expected reply type and raise `ServerError` on type `error`:
  - `request_key()` returns 32 bytes. It requires `key_result` with `key` as base64 decoding to exactly 32 bytes.
  - `request_decrypt(key, blob)` requires `decrypt_result` and returns its payload.
  - `request_verify(key, mac, data)` requires `verify_result` with `result` in `{"VERIFIED","FAILED"}` and returns a bool.
  - A reply of any other type raises `ProtocolError`.
- `FAILED` is a normal return value, not an exception [R8].

### 2.4 Crypto [R3, R25]

- `aes_encrypt(key, plaintext, nonce=None)` uses `os.urandom(12)` when no nonce is given, and returns `nonce + AESGCM(key).encrypt(nonce, plaintext, None)`. The `nonce` argument exists only so the self-check can use the fixed vector nonce.
- `sha256(data)` is `hashlib.sha256(data).digest()`.
- `custom_hmac(key, data)` computes `Ki`/`Ko` by XOR with `0x36`/`0x5c` over 32 bytes, then `sha256(ko + sha256(ki + data))`. Nothing from the `hmac` module is used.
- Key and MAC base64 helpers use `base64.b64encode` and `b64decode(validate=True)` (standard alphabet, padded).

### 2.5 Self-checks [R25, R26]

| Function | Checks |
|---|---|
| `check_framing_vector()` | `build_request({"type":"get_key","username":"student01"}, b"")` equals the Section 9 hex |
| `check_aes_vector()` | encrypting `hello world` with the vector key and nonce gives the 39-byte vector, and decrypting it gives the plaintext |
| `check_hmac_vectors()` | the `hello world` and empty-file vectors match, the inner hash matches, and the result differs from the hard-coded standard-HMAC value `411b9a51…` |

Each returns `(ok, message)`. `run_self_checks()` produces a `SelfCheckStatus(framing_ok, aes_ok, hmac_ok, messages)` at startup. These flags gate the UI:

- AES enabled means `framing_ok and aes_ok`.
- HMAC enabled means `framing_ok and hmac_ok`.
- A disabled workflow has all its controls (Get Key and Start) disabled, and an error banner plus a dialog explain why.
- The workflow functions also assert on their gate, as defense in depth.

### 2.6 Workflows

All three return a result dataclass. They take plain arguments (including already-read bytes), so they can be tested without a GUI.

**Output folder helpers [R41].**
- `default_output_dir(in_path)` returns `<folder of the input file>/results`, as an absolute path.
- `prepare_output_dir(out_dir, in_path)` creates `out_dir` with `os.makedirs` only when it is the default folder (compared after normalizing the path), then runs `check_output_dir()`. Any other folder must already exist and be writable, otherwise it raises `FileAccessError` and nothing is created. A failure to create the default folder (for example a plain file named `results`) also raises `FileAccessError`.
- `default_companion_paths(in_path)` returns the `.hmac` and `.hmackey` paths to use in saved mode. It checks each one separately: `results/<name>.hmac` (or `.hmackey`) if that file exists, otherwise `<input>.hmac` (or `.hmackey`) beside the input file, which is the spec's convention.

The workflow functions below take an `out_dir` that the caller has already prepared, and they still call `check_output_dir()` as a safety net.

**`aes_roundtrip(conn, key, in_path, out_dir) -> AesResult`**
1. Read the input file [R10, R11].
2. Resolve the output paths: `<out_dir>/<name>.enc` and `<name>.key`, plus the decrypted copy `<stem>_decrypted<ext>` (`name` is the input file's name; `decrypted_name()` inserts `_decrypted` before the last extension, so `photo.jpg` becomes `photo_decrypted.jpg` and a name with no extension just gets the suffix).
3. Encrypt locally.
4. Write `.enc`, and write `.key` as base64 text with no trailing newline [R15].
5. Send `decrypt` and receive the plaintext.
6. Compare the returned bytes with the original using plain `==`. This is not a secret comparison, and the stdlib `hmac` module is avoided anyway.
7. On a match, write the decrypted copy `<stem>_decrypted<ext>` [R16]. Return `Match` or `Mismatch` [R17].

**`hmac_compute_and_verify(conn, key, in_path, out_dir) -> HmacResult`**
1. Read the input file.
2. Compute the HMAC.
3. Write `<name>.hmac` and `<name>.hmackey` into `out_dir` as base64 text [R18].
4. Send `verify_hmac`.
5. Return `VERIFIED` or `FAILED`.

**`hmac_verify_saved(conn, in_path, hmac_path, key_path) -> HmacResult`**
1. Read the input file.
2. Read the two companion files, strip whitespace, base64-decode, and require exactly 32 bytes each, otherwise raise `ValidationError` [R19].
3. Send `verify_hmac` and return the result. The stored HMAC is sent as-is, and the client does not recompute it.

**Overwrite pre-check [R24].** `planned_outputs(workflow, ...)` returns every path a run could write, including the decrypted-copy path. The controller checks which exist and asks for confirmation on the main thread before starting the worker. Declining cancels the run before any network activity. The check happens at Start, not at Get Key. The output folder is prepared (and the default `results` folder created) just before this check and after the input file has been validated, so a rejected input never creates the folder. If the user declines the overwrite, files already in the folder are left untouched.

**Key lifetime [R22].**
- A `KeyHolder` per workflow stores `bytes | None`, with `set()`, `clear()` and `loaded` (bool).
- After a valid server reply (`Match`, `Mismatch`, `VERIFIED` or `FAILED`), the controller clears the holder.
- After any `ClientError`, the key is retained.
- If the workflow fails before the network call (for example the file is too large), the key is also retained.

## 3. GUI design

### 3.1 Layout (ttk, grid)

```
+--------------------------------------------------------------+
| [ error banner row: shown only when a self-check fails ]     |
| Connection   Host [________]  Port [8080]  Username [______] |
| Workflow     (o) AES   ( ) HMAC                              |
| ------------------------------------------------------------ |
| (selected workflow panel)                                    |
|   AES:   [Get AES Key]  Key loaded                           |
|          Input file   [_____________________] [Browse]       |
|          Output folder[_____________________] [Browse]       |
|          [Start Encrypting]                                  |
|   HMAC:  Mode (o) Compute & verify  ( ) Verify saved files   |
|          [Get HMAC Key]  Key loaded                          |
|          Input file   [____] [Browse]                        |
|          Output folder[____] [Browse]     (compute mode)     |
|          HMAC file    [____] [Browse]     (saved mode)       |
|          Key file     [____] [Browse]     (saved mode)       |
|          [Start Verifying]                                   |
| ------------------------------------------------------------ |
| [ progress bar row, fixed height, always reserved ]          |
| Status: ...                                                  |
| Result: Match / Mismatch / VERIFIED / FAILED / error         |
| Activity log (read-only text, scrolled)                      |
+--------------------------------------------------------------+
```

- Each workflow panel is a `ttk.Frame`. Switching the radio button uses `grid_remove()` on the other panel, and the `ttk.Progressbar` row has a fixed minimum height so showing or hiding it never moves other widgets [R28–R30].
- Within the HMAC panel, the mode radio buttons show only the relevant rows. Get HMAC Key is shown only in compute mode, and the saved-files rows only in saved mode [R18–R20].
- The result line uses colour and text that are distinct for each outcome. `FAILED` is displayed as a warning-style result, and `error` and connection failures use an error style, so they can't be confused [R8].
- Styling uses ttk with the `clam` theme, one font family and size scale, uniform padding, a resizable layout (columns weight 1, log row weight 1) and a `minsize` [R29, R32].
- Host, Port and Username start empty (Port defaults to 8080), and nothing is saved to disk [R27].

### 3.2 Controller and state

- `AppState` holds the selected workflow, the HMAC mode, `KeyHolder` for AES, `KeyHolder` for HMAC, `SelfCheckStatus`, and `busy`.
- Start is enabled only when:
  - the workflow is enabled by the self-checks;
  - the app isn't busy;
  - a fetched key is loaded (AES, and HMAC compute mode), or the three file paths are filled in (HMAC saved mode).

  A single `refresh_controls()` recomputes every widget state.
- Selected paths are `tk.StringVar` values, so they are visible and editable before starting [R29]. In saved mode, picking the input file auto-fills the `.hmac` and `.hmackey` paths from `default_companion_paths()` (changeable by the user), and the lookup is repeated when the HMAC mode is switched, so files just saved in `results/` are found [R20]. The Output folder field is filled with `default_output_dir()` when the input is chosen, unless the user has typed their own value. An empty field falls back to the same default at Start [R41].
- The Key loaded label shows only that text, with no key characters [R23].

### 3.3 Background threading [R30, R33, R34]

- Each action (Get Key, Start) is a function run on a `threading.Thread(daemon=True)`. It never touches Tk widgets. Its outcome is put on a `queue.Queue` as `("ok", result)` or `("error", ClientError)`, plus `("log", text)` messages.
- The main thread polls the queue with `root.after(50, ...)`, updates widgets, and re-enables controls when the task ends.
- Start sequence on the main thread: validate connection fields → check file existence/size where cheap → prepare the output folder (create the default `results` folder) → overwrite confirmation → set busy, start the progress bar → start the worker.
- Closing the window while busy asks for confirmation and then destroys the window. The daemon thread is abandoned.

### 3.4 Logging

- `ActivityLog.add(text)` appends to the read-only Text widget (state toggled only inside this method). Callers pass only messages built from file names, sizes and outcomes.
- Functions that handle keys never receive the logger, and exception messages are built without key data. The username is not logged.

## 4. Mock server (`mock_server.py`) [R35, R36]

- `socketserver.ThreadingTCPServer` bound to `127.0.0.1` and an OS-chosen port. A `MockServer` class can be started and stopped from tests and exposes `.port`. It can also run from the command line with a fixed port.
- It implements Section 3 framing with its own `recv_exact`, a username check (the same character rules, plus a configurable set of accepted users), the 1000-byte header limit and the 1 MiB payload limit. Violations return the generic `error`.
- Commands:
  - `get_key` returns a random 32-byte key in `key_result`.
  - `decrypt` base64-decodes the key, splits the blob into nonce, ciphertext and tag, and decrypts with `AESGCM`. Failures return `error`.
  - `verify_hmac` recomputes the HMAC with the mock's own implementation, which is written separately from the client's. It returns `verify_result` with `VERIFIED` or `FAILED`. Malformed key or hmac returns `error`.
- Fault modes are set at construction time:

| Mode | Behaviour |
|---|---|
| `normal` | correct behaviour |
| `always_error` | every request gets `error` |
| `drop_connection` | close the socket right after accepting |
| `drop_mid_reply` | send a partial reply, then close |
| `timeout` | accept and never reply |
| `bad_reply` | garbage header, wrong type, oversized `payload_len` |
| `tamper_decrypt` | return a decrypted payload with one byte changed (to produce `Mismatch`) |

- `exchange()` takes its timeout as a module-level default of 30 seconds that tests can override, so timeout tests don't take 30 seconds.
- `test_mock_server.py` validates the mock's HMAC against the Section 9 vectors, independent of the client's code [R36, R38].

## 5. Traceability

| Area | Requirements | Where |
|---|---|---|
| Dependencies / stdlib-only crypto | R1–R4 | `custom_hmac`, `sha256`, `requirements.txt` |
| Protocol, timeouts, reply validation | R5–R8 | `build_request`, `exchange`, `read_reply`, typed wrappers |
| Input validation and limits | R9–R13 | `validate_*`, `read_input_file`, `save_*` |
| AES workflow | R14–R17 | `aes_roundtrip` |
| HMAC workflow | R18–R20 | `hmac_compute_and_verify`, `hmac_verify_saved`, `default_companion_paths`, controller auto-fill |
| Key handling | R21–R23 | `KeyHolder`, controller, `ActivityLog` rule |
| Overwrite safety | R24 | `planned_outputs`, Start sequence |
| Output location | R41 | `default_output_dir`, `prepare_output_dir`, `default_companion_paths`, controller auto-fill |
| Self-checks | R25–R26 | `check_*`, `SelfCheckStatus`, `refresh_controls` |
| UI | R27–R34 | GUI layout, controller, threading |
| Testing | R35–R38 | `mock_server.py`, `tests/` |
| Structure / docs | R39–R40 | layout in Section 1, README |

## 6. Implementation order (follows spec Section 11, recommended)

1. Skeleton, validation, framing and `recv_exact`, with `check_framing_vector()` and tests.
2. AES encrypt, with `check_aes_vector()` and tests, before any networking.
3. `mock_server.py` with `get_key`, then the client's `request_key()` against it.
4. `aes_roundtrip` against the mock server, including the `Mismatch` path, with a byte-for-byte comparison.
5. `custom_hmac` and `check_hmac_vectors()`, then the mock's independent HMAC, then both HMAC modes.
6. Fault modes and error-path tests.
7. GUI shell, then wiring, threading, self-check gating, and the smoke test.
8. README, then a manual run against the real server when the instructor provides details.

## 7. Design decisions to confirm

- **D1.** Key and HMAC files are written as base64 text with no trailing newline. Reading accepts surrounding whitespace.
- **D2.** The `.enc` and `.key` files, and `.hmac` and `.hmackey`, are written before the network call, as approved. The decrypted copy (`<stem>_decrypted<ext>`) is only written on a match.
- **D3.** Reply header length is capped at 1000 bytes (the spec's header limit). Reply `payload_len` is capped at 1 MiB.
- **D4.** Reading input files is capped at `limit + 1` bytes, so a very large file is never loaded in full.
- **D5.** The server's `error` detail text is shown to the user as-is (it is generic), and truncated to a safe length.
- **D6.** The overwrite check includes the decrypted-copy path, even though it is written only on success.
- **D7.** *(Added with the `results` folder change.)* Only the default `results` folder is created automatically. A folder chosen with Browse (or typed) must already exist, so a typo cannot silently create a new folder.
- **D8.** *(Added with the `results` folder change.)* In saved mode each companion file is taken from `results/` if it exists there and otherwise from beside the input file. This keeps files saved by this app and files from other clients (the spec's convention) both working.
