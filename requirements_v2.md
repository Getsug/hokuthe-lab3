# Crypto Client — Requirements (v2)

## Overview

The application is a Python program with a Tkinter graphical user interface. It acts as a TCP client for the crypto server described in `crypto_message_spec_v2.md`, which is the authoritative reference for the wire format, file formats and algorithms. The user enters the server Host, Port and Username in the GUI.

The application provides two independent workflows:

- **AES:** fetch a random 256-bit key from the server, encrypt a user-selected file locally with AES-256-GCM, send the encrypted file and key to the server, receive the decrypted bytes, and compare them with the original file.
- **HMAC:** compute the course's custom HMAC over a user-selected file and have the server answer `VERIFIED` or `FAILED`. The user can do this either immediately, using a freshly fetched key, or later, using previously saved `.hmac` and `.hmackey` files.

Protocol details defined in `crypto_message_spec_v2.md` are not repeated here.

## 1. Platform and Dependencies

- **R1.** The application shall be written in Python 3.14 or later and shall use Tkinter with ttk for the GUI.
- **R2.** The application shall use only the standard library and the `cryptography` package (for AES-GCM). `requirements.txt` shall state a minimum compatible `cryptography` version, verified against Python 3.14 when the file is created.
- **R3.** SHA-256 shall be obtained from `hashlib`. The standard `hmac` module and any other standard HMAC implementation shall not be used.
- **R4.** The application shall target Windows 11 first while remaining cross-platform.

## 2. Protocol Compliance

- **R5.** All client-server communication shall follow `crypto_message_spec_v2.md`, and the compliance checklist in its Section 12 shall be satisfied.
- **R6.** Each request shall use its own connection, with 30-second connect and socket-read timeouts.
- **R7.** Every reply shall be validated. An unexpected, malformed, oversized or truncated reply shall produce a clear error and end the exchange.
- **R8.** A `verify_result` of `FAILED` shall be displayed differently from an `error` reply or a connection failure.

## 3. Input Validation

- **R9.** Before every request, including Get Key, the application shall validate the Username (per the spec), the Host (a non-empty IP address or hostname with no whitespace or URL syntax) and the Port (1–65535). Invalid input shall produce a client-side error without contacting the server.
- **R10.** Each input file shall be read once, in binary mode. The number of bytes actually read shall be checked against the workflow's limit in Section 8 of the spec: 1,048,548 bytes for AES plaintext and 1,048,576 bytes for HMAC files.
- **R11.** A file over its limit shall be refused before any connection is opened, and the error shall name the file and its size.
- **R12.** Empty files shall be accepted in both workflows.
- **R13.** File read errors, missing or read-only output folders, and failed writes shall each produce a clear error message.

## 4. AES Workflow

- **R14.** The user shall fetch an AES key, select an input file and an output folder, and start the run. The run encrypts locally, sends the encrypted file and key to the server for decryption, and compares the returned bytes with the original.
- **R15.** The application shall save `<file>.enc` and `<file>.key` using the spec's naming convention, immediately after local encryption and before the network request.
- **R16.** The application shall save the returned decrypted file as `<file>.decrypted` only after a byte-for-byte match with the original.
- **R17.** The result shall be displayed as **Match** or **Mismatch**.

## 5. HMAC Workflow

The HMAC workflow has two modes, chosen by a mode toggle.

- **R18.** *Compute & verify:* using a fetched key, the application computes the HMAC locally, saves `<file>.hmac` and `<file>.hmackey` before the network request, sends `verify_hmac`, and displays the result.
- **R19.** *Verify saved files:* the user selects a file and its `.hmac` and `.hmackey` files. The application shall validate that both companion files contain base64 text decoding to exactly 32 bytes, then send `verify_hmac`. No key fetch is required in this mode.
- **R20.** In *Verify saved files* mode, selecting the file shall auto-fill the `.hmac` and `.hmackey` paths from the spec's naming convention. The user shall be able to change them.

## 6. Key Handling

- **R21.** The AES and HMAC workflows shall each hold their own in-memory key, and a key shall never be used across workflows. A workflow's Start control that needs a fetched key shall stay disabled until that workflow has one.
- **R22.** Keys shall be single-use. Fetching a new key replaces the previous one. A key shall be cleared when the server returns a valid reply (Match, Mismatch, `VERIFIED` or `FAILED`) and retained after an error or connection failure so the user can retry.
- **R23.** The UI shall show only "Key loaded" and shall never display key material. Keys shall be written only to the companion files the spec requires and shall never be logged.

## 7. File Overwrite Safety

- **R24.** The application shall ask for confirmation before overwriting any existing file. The confirmation shall happen before any network activity, and declining shall cancel the run.

## 8. Startup Self-Checks

- **R25.** At startup the application shall run these checks:
  - `check_hmac_vectors()`: both HMAC vectors from Section 9 of the spec, plus confirmation that the result differs from the known standard-HMAC value given there.
  - `check_aes_vector()`: AES-GCM encryption and decryption against the Section 9 vector.
  - A framing check against the Section 9 `get_key` vector.
- **R26.** If an HMAC or AES self-check fails, that entire workflow (including Get Key and Start) shall be disabled while the other workflow stays available. If the framing check fails, both workflows shall be disabled. An error banner and an error dialog shall explain the failure.

## 9. User Interface

- **R27.** The UI shall provide Host, Port (default 8080) and Username fields. None of these values shall be persisted between launches.
- **R28.** A radio-button selector shall choose the workflow, and only the selected workflow's controls shall be visible.
- **R29.** Each workflow shall have its own **Get Key** action (where a key is needed), Browse buttons for input files and the output folder, and a Start control labelled **Start Encrypting** or **Start Verifying**. Selected paths shall be visible and changeable before starting.
- **R30.** The UI shall reserve a fixed layout row for an indeterminate progress bar so that showing or hiding it does not shift other widgets. Operation controls shall be disabled while an operation is running and restored afterwards.
- **R31.** The UI shall provide a status line and a small read-only activity log. Neither shall ever contain keys or credentials.
- **R32.** The design shall use ttk with consistent fonts and spacing, a resizable layout and a sensible minimum window size.
- **R33.** Networking and cryptographic work shall run in background threads, and Tk widgets shall be updated only from the main thread.
- **R34.** Closing the window while an operation is running shall be allowed after a confirmation prompt, and the background work shall then be abandoned.

## 10. Testing

- **R35.** The project shall include `mock_server.py`, a local server supporting successful operations, `FAILED` verification, malformed requests, oversized payloads, timeouts and dropped connections.
- **R36.** The mock server shall use its own independent HMAC implementation, validated against the Section 9 vectors.
- **R37.** Automated tests shall use `unittest` and the mock server only. Real-server testing shall be manual, and credentials shall never be hard-coded or committed.
- **R38.** All cryptographic implementations shall be validated against the Section 9 test vectors independently of the mock server.

## 11. Project Structure and Documentation

- **R39.** `crypto_client.py` shall contain the application, GUI, networking and cryptographic code. `mock_server.py`, `tests/` and `requirements.txt` shall sit beside it.
- **R40.** `README.md` shall cover installation, setup, usage, testing, project structure and generated files. It shall also include a security note that the teaching server uses unencrypted TCP.

## Development Guidelines

These are guidance and are not numbered requirements.

- Build and test incrementally, following the order recommended in Section 11 of the spec.
- If a requirement is unclear, ask for clarification instead of assuming.
- The reference to `crypto_message_spec_v1.md` in Section 11 of the spec is a typo, and v2 is authoritative.
