# Crypto Client

A Tkinter desktop client for the course crypto server. It demonstrates two operations:

- **AES-256-GCM:** the app fetches a key from the server, encrypts a file locally, has the server decrypt it, and checks that the returned bytes match the original.
- **HMAC:** the app computes the course's custom HMAC over a file, and the server checks it. This is not standard HMAC (RFC 2104).

The protocol, file formats and algorithms are defined in `crypto_message_spec_v2.md`.

> **Security note:** the teaching server uses plain, unencrypted TCP. Keys and files cross the network in the clear, and the username is the only credential. Do not send real secrets.

## Setup

Requires Python 3.14 or later (with Tkinter) and the `cryptography` package.

```
python -m pip install -r requirements.txt
python crypto_client.py
```

## Usage

1. Enter the **Host**, **Port** (default 8080) and **Username** provided by your instructor. These are not saved between runs.
2. Choose **AES** or **HMAC** with the operation buttons.
3. Click **Get AES Key** or **Get HMAC Key**, then browse to an input file and click **Start**. The window shows only "Key loaded", never the key.
   For HMAC you can instead choose **Verify saved files** to check a file against its existing `.hmac` and `.hmackey` files, with no key needed.

### Results

The outcome appears in the result line below the Start button, with details in the activity log at the bottom of the window.

| Operation | Result shown |
|---|---|
| AES | **Match** or **Mismatch** |
| HMAC | **VERIFIED** or **FAILED** |

Errors (such as a bad username, a connection problem or an oversized file) are shown as a separate red message and a dialog. A **FAILED** verification is a normal result, not an error.

### Saved files

Files are saved next to the input file, or in the output folder you choose, and the app asks before overwriting anything. For an input file `report.txt`:

- **AES:** `report.txt.enc`, `report.txt.key`, and `report.txt.decrypted` (only after a Match)
- **HMAC:** `report.txt.hmac` and `report.txt.hmackey`

## Testing

```
python -m unittest discover -s tests
```

The tests use a local mock server (`mock_server.py`) and need no real server. GUI tests are skipped if no display is available. To try the app without the real server, run `python mock_server.py --port 8080`, then connect to host `127.0.0.1`, port `8080`, with any valid username.
