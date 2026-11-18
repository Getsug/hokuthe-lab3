### Overview

The application is a Python program with a Tkinter graphical user interface that acts as a client for a remote crypto server. It performs two independent operations. First, it fetches a random 256-bit AES key from the server, encrypts a user-selected file locally using AES-256-GCM, sends the encrypted blob and the key back to the server, and receives the decrypted plaintext. If the returned bytes match the original file exactly, the AES workflow is correct. Second, it fetches a random 32-byte key from the server, computes a message authentication code over a user-selected file using the course's custom HMAC construction, sends the file, key, and MAC to the server and displays whether the server responds `VERIFIED` or `FAILED`. The client communicates over plain TCP using the message framing, header fields, file formats and HMAC algorithm defined in `crypto_message_spec_v2.md`, which is the authoritative reference for the wire format and algorithms


### Project Requirements

1. The application will be developed in Python.
2. Use **Python 3.14.7** as the programming language, with compatibility verified for Tkinter and the `cryptography` package.
3. Use Tkinter for the Graphical User Interface (GUI).
4. The project should include a `README.md`  that explains installation, application startup, usage, testing and project structure.
5. The deliverable Python file should be named `crypto_client.py`    
6.  The application shall make use of Python's standard library and the `cryptography` package required for AES-GCM.  Any unnecessary third-party dependencies shall be avoided.
7.  **The application must strictly follow** `crypto_message_spec_v2.md` **as the authoritative reference for all client-server communication, including connection handling, message formats, requests, and responses.**
8. The program shall validate the username against the character and length rules in `crypto_message_spec_v2.md` before opening a connection and shall surface a client-side error without contacting the server if the username is rejected.
9. The program shall implement the AES workflow as specified in `crypto_message_spec_v2.md`.
10. The program shall implement the HMAC workflow as specified in `crypto_message_spec_v2.md`.
11. The program shall hard-code the HMAC test vectors from Section 9 of `crypto_message_spec_v2.md` and shall run the custom HMAC function against them at startup via `check_hmac_vectors()`. If any vector does not match, the program shall refuse to send `verify_hmac` requests and shall show an error explaining that the HMAC implementation is incorrect.
12. The program shall also expose the AES-GCM test vector from Section 9 of `crypto_message_spec_v2.md` as a `check_aes_vector()` function and shall run it at startup. If it does not match, the program shall refuse to send `decrypt` requests and shall show an error explaining that the AES-GCM implementation is incorrect.
13. The program should check the size of the file to be sent against the payload limit in Section 8 of `crypto_message_spec_v2.md` before opening a connection and shall refuse to send if the limit would be exceeded, showing a client-side error that names the file and its size.
14. The UI should provide separate **Get AES Key** and **Get HMAC Key** actions. Each workflow should maintain its own in-memory key state to prevent accidental cross-workflow key reuse.
15. The UI should provide an operation selector and a **Start** control whose label changes to **Start Encrypting** or **Start Verifying**, depending on the selected workflow.
16. The UI should provide **Browse** buttons for selecting input files and output locations for both AES and HMAC . Selected file paths shall be displayed in the interface, and users shall be able to change their selections before starting an operation.
17. The UI should reserve a fixed area for a progress indicator so that displaying or hiding it does not cause other interface elements to shift.
18. The GUI shall use a clean, modern and consistent visual design.
19. The application shall be implemented and tested incrementally, following the recommended development sequence in Section 11 of crypto_message_spec_v2.md.
20. The project shall include a local mock server for integration testing, and all cryptographic implementations shall be independently validated against the test vectors in Section 9.
21. The implementation shall satisfy the compliance checklist in Section 12 of crypto_message_spec_v2.md. Any unclear requirements shall be clarified before implementation rather than assumed.