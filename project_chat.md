# Project Chat Log — Lab 3 Crypto Client

A record of the working session. Short user messages are quoted as sent. Long messages and all assistant replies are summarized. Tool output (file contents, test logs) is omitted, but the files and results it produced are named.

---

## 1. Requirements review

**User:** Do not implement anything yet. Review `requirements_v1.md`, identify ambiguities, missing requirements, inconsistencies and edge cases. Ask questions, do not modify `requirements_v1.md`, wait for answers, and once approved generate `requirements_v2.md`.

**Assistant:** Read `requirements_v1.md` and `crypto_message_spec_v2.md`, then asked 28 numbered questions in groups, each with a suggested default:
- **A. Scope and workflow:** single run vs saved artifacts, output files, key lifetime, key display, overwrite policy, AES comparison.
- **B. Connection and credentials:** Host/Port/Username input, validation timing, timeouts, reply handling.
- **C. Limits and edge cases:** per-workflow size limits, empty files, file and output errors.
- **D. Self-checks:** failure behaviour, which vectors, `hashlib` use.
- **E. UI:** selector, progress bar, log, appearance, threading.
- **F. Project:** Python version, file layout, test tooling, mock-server correctness, README.
- **G. Text issues:** mixed "should"/"shall", Req 19 and 21 wording, a `v1` typo in the spec.

## 2. User's answers

**User:** Answered all questions (A–G). Key decisions:
- AES does a full encrypt/decrypt round trip. HMAC supports immediate verification and verification from saved `.hmac`/`.hmackey` files. Standalone AES decryption is out of scope.
- Keys are single-use, shown only as "Key loaded", and overwrites always need confirmation.
- Host, Port and Username fields, nothing persisted, validated before every request.
- 30 s timeouts, no Cancel button.
- A failed self-check disables the affected workflow; vectors include both HMAC vectors, the standard-HMAC value, AES and framing.
- `hashlib.sha256`, no standard HMAC.
- Radio-button selector, indeterminate progress bar, status line plus activity log, ttk, background threads.
- Python 3.14+, `crypto_client.py` plus `mock_server.py` and `tests/`, `unittest`, an independent mock HMAC, manual real-server testing only.
- Use "shall" consistently and keep requirements short. Then: propose revisions and list remaining inconsistencies, but create nothing yet.

**Assistant:** Proposed the full v2 requirements text (R1–R35) and listed nine remaining issues, each with a proposal:
1. Saved-file HMAC verification conflicts with "Start disabled until key fetched".
2. When files are saved relative to the network call.
3. When a key counts as spent.
4. A name for the decrypted file.
5. Self-check scope.
6. Auto-filling saved-file paths.
7. Host validation rules.
8. Closing the window while busy.
9. The `cryptography` minimum version.

## 3. requirements_v2.md

**User:** "This is inline with what I expect. Proceed with the generation of requirements_v2.md"

**Assistant:** Created `requirements_v2.md` with 40 requirements, including all nine proposals. It noted that the `cryptography` minimum version was left to be verified, and that the key-clearing rule and the `.decrypted` name were its own choices.

## 4. interrogation.md (started)

**User:** Simply computing SHA256(K || message) can be vulnerable to length-extension attacks. Explain how the nested construction prevents it and why the inner and outer keys are derived differently. Add this to `interrogation.md`.

**Assistant:** Created `interrogation.md` with Q1 and Q2:
- **Length extension:** a SHA-256 digest is the hash's internal state, so `SHA-256(K||m)` can be extended without the key. In the nested form only the outer digest is exposed, so the attacker cannot extend the inner hash.
- **Different keys:** `0x36 XOR 0x5c = 0x6a`, so `Ki` and `Ko` differ in every byte. This gives domain separation.
- **Caveat:** the lab construction is not RFC 2104 HMAC (no 64-byte key padding), so published HMAC proofs should not be quoted for it.

## 5. design_v1.md

**User:** Generate `design_v1.md` and give a summary for approval. Do not implement yet.

**Assistant:** Created `design_v1.md` and summarized it:
- Layered single-file client (GUI, workflows, transport, crypto/validation/IO).
- A `ClientError` family.
- Self-check gating flags.
- Workflow sequences.
- A GUI layout with a queue-based worker-thread design.
- A mock server with fault modes.
- A traceability table.
- An eight-step build order.
- Six decisions D1–D6 to confirm.

## 6. Implementation

**User:** Approved `design_v1.md` including D1–D6. Read the spec, implement according to the design in the Section 6 build order. For each stage: implement only what that stage needs, write and run tests, verify against the Section 9 vectors, fix failures first, and add nothing outside the requirements.

**Assistant:** Implemented in seven stages and ran the tests after each one:

| Stage | Built | Tests after stage |
|---|---|---|
| 1 | Validation, framing, `recv_exact` | 17 |
| 2 | AES-GCM and `check_aes_vector` | 25 |
| 3 | Transport, reply validation, mock server (`get_key`) | 34 |
| 4 | AES round trip, mock decrypt, Mismatch path | 42 |
| 5 | Course HMAC, both modes, independent mock HMAC | 63 |
| 6 | Fault modes and error-path tests | 78 |
| 7 | GUI, self-check gating, GUI tests | 99 |

Notable events:
- Python 3.14.7 was present and `cryptography` was installed (50.0.2).
- A bash heredoc failed twice because of quoting. The assistant checked that nothing had run, then used file tools instead.
- **Real bug found by a test:** a read timeout was reported as a vague "network error". `recv_exact` now reports the timeout clearly.
- **Noise fixed:** the poll timer and progress bar kept firing after the window was destroyed, so `App.shutdown()` now cancels them.
- **Dependency:** `cryptography>=46.0.0` was chosen after running the crypto, workflow and fault tests against 46.0.0 and 50.0.2.
- Created `crypto_client.py`, `mock_server.py`, `tests/`, `requirements.txt` and `README.md`.
- Launched the real GUI briefly with no errors.
- Nothing was committed, and there was no real-server run.

## 7. More interrogation.md questions

**User:** Why does our protocol use a four-byte big-endian header length when TCP already guarantees reliable delivery? Append to `interrogation.md`.
**Assistant:** Added **Q3**:
- TCP preserves byte order and delivery but not message boundaries.
- A length prefix is the simplest framing that suits binary data.
- It allows cheap rejection of oversized lengths.
- Four bytes is the standard fixed width.
- Big-endian is network byte order and is confirmed by the spec vector `00 00 00 39`.
- The length counts bytes, not characters.

**User:** Why does our design use AES-GCM instead of AES-CBC? What advantages does GCM provide? Append to `interrogation.md`.
**Assistant:** Added **Q4**:
- The spec fixes GCM, so it was not our design's choice.
- GCM is authenticated encryption: it detects tampering, needs no padding, adds a fixed 28 bytes, and is parallelizable.
- CBC gives confidentiality only and has padding-oracle risks.
- Cautions: never reuse a nonce, verify the tag before using plaintext, and no AAD is used.
- GCM and the course HMAC protect different things.

**User:** My HMAC computes `sha256(ko + sha256(ki + data))`. Why must the inner hash be a 32-byte digest and not a 64-character hex string, and how would `.hexdigest()` affect the result? Append to `interrogation.md`.
**Assistant:** Computed both values for the Section 9 vector and added **Q5**:
- `.digest()` gives `585c65e6…` (matches the spec).
- `.hexdigest()` gives `e02957ea…` (wrong).
- Hashing hex text is a different byte input, so the result is unrelated.
- The server would reply `FAILED`, not `error`.
- `check_hmac_vectors()` catches the mistake at startup.

## 8. README rewrite

**User:** Update `README.md` to be more concise, professional and easy to understand. It should:
1. Briefly explain the AES-256-GCM and HMAC problems.
2. Include essential install and start commands.
3. Say where results appear and where files are saved.
4. Include the test command.
5. Keep a brief security note about unencrypted TCP.
6. Remove technical detail, the detailed project structure and lengthy file descriptions.
It should not present generated files as extra deliverables. Modify only `README.md`.

**Assistant:** Rewrote `README.md` from about 92 lines to 52. It flagged that requirement R40 (README covers project structure) now disagrees with the shorter README, and offered to add a pointer or update R40.

## 9. This log

**User:** "add this chat to project_chat.md"

**Assistant:** Created this file.

## 10. .gitignore

**User:** "add a .gitignore"

**Assistant:** Created `.gitignore` covering Python clutter, editor and OS files, and the app's generated files (`*.key`, `*.hmackey`, `*.enc`, `*.hmac`, `*.decrypted`) so real keys are not committed by accident. `__pycache__/` stopped appearing in `git status`. The user later edited the file themselves, adding more Python tool caches, virtual-environment names and a Claude Code local-settings entry.

## 11. Decrypted file naming change

**User:** Update the decrypted file naming convention to preserve the original extension by inserting `_decrypted` before it (for example `photo.jpg` becomes `photo_decrypted.jpg`). Apply it consistently across the implementation, tests, README and design documentation. Preserve existing functionality and do not modify `crypto_message_spec_v2.md` or `requirements_v1.md`.

**Assistant:** Made the change and ran the full suite (102 tests, all passing):
- **Code:** added `decrypted_name()`, which splits at the last extension, and `aes_output_paths()` now uses it. `.enc` and `.key` keep the spec's naming. The overwrite check picks up the new path automatically.
- **Edge cases:** `archive.tar.gz` becomes `archive.tar_decrypted.gz`, `README` becomes `README_decrypted`, and `.bashrc` becomes `.bashrc_decrypted`.
- **Tests:** updated the old expectations in `test_workflows.py` and `test_gui_smoke.py`, and added tests for the naming rule and for the overwrite check covering the new path.
- **Docs:** updated `README.md` and `design_v1.md`. Also updated R16 in `requirements_v2.md`, which was not on the user's list but would otherwise have contradicted the code.
- **Left alone:** the spec, `requirements_v1.md`, and the `.gitignore` rule `*.decrypted`, which was now stale. It flagged that the old name also still appears in section 3 of this log, as history.

## 12. .gitignore update and this log

**User:** "update .gitignore and add append this to project_chat.md"

**Assistant:**
- **`.gitignore`:** replaced the stale `*.decrypted` rule with `*_decrypted.*` and `*_decrypted`, and removed a duplicated Claude Code settings block. Checked that `photo_decrypted.jpg`, `README_decrypted` and `archive.tar_decrypted.gz` are ignored, and that source, tests and docs are not.
- **This log:** added sections 10–12 and refreshed the closing file list and open items, which were out of date (they said there was no `.gitignore` and counted 99 tests).

---

## Files produced in this session

| File | Purpose |
|---|---|
| `requirements_v2.md` | Approved requirements (R1–R40) |
| `design_v1.md` | Approved design (D1–D6) |
| `crypto_client.py` | The application (validation, framing, transport, crypto, workflows, self-checks, GUI) |
| `mock_server.py` | Local mock server with its own HMAC and fault modes |
| `tests/` | 102 `unittest` tests (all passing at last run) |
| `requirements.txt` | `cryptography>=46.0.0` |
| `README.md` | Setup, usage, results and testing |
| `interrogation.md` | Written answers Q1–Q5 (plus the HMAC caveat) |
| `project_chat.md` | This log |
| `.gitignore` | Ignores caches, editor files and the app's generated key, encrypted and decrypted files |

## Open items

- Real-server testing has not been done. It needs the host and username from the instructor.
- R40 and the shortened `README.md` disagree about including project structure.
- Nothing has been committed.
