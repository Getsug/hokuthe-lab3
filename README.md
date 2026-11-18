# Crypto Client

A Tkinter desktop client for the course crypto server. The server hands out random keys, and the client uses them for two tasks:

- **AES-256-GCM encryption:** the client encrypts a file locally, the server decrypts it, and the client checks that the result matches the original file.
- **HMAC integrity checking:** the client computes the course's custom HMAC for a file, and the server confirms whether the file and HMAC match. This is not standard HMAC (RFC 2104).

The protocol and algorithms are defined in `crypto_message_spec_v2.md`.

> **Security note:** the server uses plain, unencrypted TCP. Keys and files cross the network in the clear, and the username is the only credential. Do not send real secrets.

## Setup

Requires Python 3.14 or later (with Tkinter) and the `cryptography` package.

```
python -m pip install -r requirements.txt
python crypto_client.py
```

## Server configuration

Fill in the **Server** section at the top of the window before any request:

| Field | What to enter |
|---|---|
| **Host** | The server's IP address, as given by your instructor (a host name such as `localhost` also works) |
| **Port** | The server's port (default `8080`) |
| **Username** | Your assigned username: 1–32 characters from `A-Z a-z 0-9 _ . -` |

These values are not saved between runs. Invalid values are rejected without contacting the server.

## Walkthrough

### AES
1. Select **AES encrypt / decrypt**.
2. Click **Get AES Key**. The window shows "Key loaded" (never the key itself).
3. Click **Browse...** next to *Input file* and choose a file. The *Output folder* fills in with a `results` folder next to that file. Click **Browse...** beside it to choose a different folder.
4. Click **Start Encrypting**.

### HMAC
1. Select **HMAC verify**.
2. Choose a mode:
   - **Compute & verify:** click **Get HMAC Key**, browse to an input file (the output folder defaults to `results` next to it, or choose another), then click **Start Verifying**.
   - **Verify saved files:** browse to the input file. Its `.hmac` and `.hmackey` paths fill in automatically (from the `results` folder if they are there, otherwise from next to the file), and you can change them. Click **Start Verifying**. No key is needed.

A key can be used for one run. After the server gives a valid reply you must fetch a new key. If an error occurs, the key is kept so you can retry.

## Results and saved files

The outcome appears in the result line just below the Start button, with more detail in the **Activity** log at the bottom of the window.

| Workflow | Result shown |
|---|---|
| AES | **Match** or **Mismatch** |
| HMAC | **VERIFIED** or **FAILED** |

**FAILED** is a normal answer (the HMAC does not match the file and key). Errors, such as a bad username, an unreachable server or a file over the size limit, appear as a red message and a dialog instead.

Files are saved in the **Output folder**. By default this is a `results` folder next to the input file, which the app creates for you if it does not exist. A folder you choose yourself must already exist. The app asks before overwriting an existing file.

| File | Written by | Saved as, for `photo.jpg` |
|---|---|---|
| Encrypted file | AES | `results/photo.jpg.enc` |
| AES key | AES | `results/photo.jpg.key` |
| Decrypted copy, only after a Match | AES | `results/photo_decrypted.jpg` |
| HMAC | HMAC (compute) | `results/photo.jpg.hmac` |
| HMAC key | HMAC (compute) | `results/photo.jpg.hmackey` |

The decrypted copy keeps the original extension, with `_decrypted` added before it. A name with no extension, such as `README`, becomes `README_decrypted`.

## Testing

Run the automated tests (they use a built-in local mock server, so no real server is needed):

```
python -m unittest discover -s tests
```

To use the app without the real server, start the mock server in a separate terminal:

```
python mock_server.py --port 8080
```

Then run the app with Host `127.0.0.1`, Port `8080` and any valid username. The mock server only accepts connections from the same computer.
