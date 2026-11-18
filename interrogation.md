# Interrogation — Lab 3 HMAC

## Q1. How does the nested construction prevent length-extension attacks?

### The attack on SHA-256(K || m)

SHA-256 is a Merkle–Damgård hash. It processes the input in 64-byte blocks and carries a 256-bit internal state from block to block. The final digest is that internal state after the last block, which includes the padding (`0x80`, zeros, and the 64-bit message length).

A naive MAC `T = SHA-256(K || m)` therefore hands the attacker the exact internal state the hash had after processing `K || m || padding`. Suppose the attacker knows `m`, `T`, and the length of `K` (32 bytes here, and it is public). They can:

1. Work out the padding that was appended to `K || m`.
2. Load `T` as the starting state of a new SHA-256 computation.
3. Hash any suffix `s` from there.

The result is a valid tag for `m || padding || s`, and the attacker never learned `K`.

### Our construction

```
HMAC(K, x) = SHA-256( Ko || SHA-256( Ki || x ) )
```

The attacker only ever sees the **outer** digest. The inner digest `SHA-256(Ki || x)` is never transmitted, so the attacker does not know the state that matters for message extension.

Trying to extend the outer hash does not help either:

- Extending the outer hash gives `SHA-256(Ko || inner || padding || s)`. This is the hash of a longer outer input, and it is not the HMAC of any message.
- A valid tag for a longer message `x' = x || padding' || s` must equal `SHA-256(Ko || SHA-256(Ki || x'))`. Computing the inner hash of `x'` requires extending `SHA-256(Ki || x)`, which means knowing the inner digest. The attacker does not have it.
- The outer hash always takes exactly 64 bytes of input (`Ko`, 32 bytes, plus the inner digest, 32 bytes). A tag can only be valid if it was produced from exactly this structure.

In short, the outer hash "finalizes" the computation. The value on the wire is a hash of a hash, so it is not the internal state of the hash that processed the message.

## Q2. Why are the inner and outer keys derived differently (`0x36` vs `0x5c`)?

`Ki = K XOR 0x36…36` and `Ko = K XOR 0x5c…5c`. Because `0x36 XOR 0x5c = 0x6a`, `Ki` and `Ko` differ in every byte, and half of their bits (128 of 256) differ.

This is **domain separation**. The inner and outer hashes behave like two different keyed functions instead of the same function applied twice.

If both used `K` directly, the construction would be `SHA-256(K || SHA-256(K || x))`. The tag of `x` would then equal the naive prefix-MAC `SHA-256(K || y)` of the 32-byte message `y = SHA-256(K || x)`. The outer step would be the same vulnerable primitive applied to the inner output, so a value produced in one role could be reused in the other.

With distinct derived keys, an inner result can never be treated as an outer one, and the two stages are not related by a single key-independent function. The fixed constants also keep both derived keys dependent on all of `K`, with no extra secret needed.

## Caveat: this is not RFC 2104 HMAC

The course design differs from standard HMAC:

- **Standard HMAC** pads the key to the hash block size (64 bytes for SHA-256) before the XOR. `Ki` and `Ko` therefore fill exactly one compression-function block each.
- **The lab version** XORs the unpadded 32-byte key and applies no block padding.

Its output intentionally does not match Python's `hmac` module or OpenSSL. In the spec's test vector, a standard HMAC gives `411b9a51…`, but this construction gives `585c65e6…`.

The length-extension argument above (the attacker never sees the inner digest) holds for the lab construction. The published security proofs for HMAC assume the standard padded form, so they should not be quoted as proving this variant secure. That is why the client implements Section 6 of `crypto_message_spec_v2.md` by hand and checks it against the Section 9 vectors at startup (`check_hmac_vectors()`).


## Q3. Why a four-byte big-endian header length, when TCP already guarantees reliable delivery?

### What TCP guarantees, and what it doesn't

TCP guarantees that bytes arrive **intact, in order, and without loss or duplication**. It does **not** preserve message boundaries. It is a byte stream, not a message stream.

- One `send()` of 500 bytes may arrive as several `recv()` results (for example 200 + 300).
- Several `send()` calls may be merged into one `recv()`.
- Nothing in the stream says where one message ends and the next begins.

Reliable delivery answers "did my bytes arrive correctly?". Framing answers "which of those bytes make up one message?". They solve different problems. The spec says this directly: "One `recv()` call may return less than you asked for. Always loop until you have read exactly the number of bytes you need."

### What the length prefix does

Every message is `[4-byte length][JSON header][payload]`. The receiver:

1. Reads exactly 4 bytes, which gives `header_len`.
2. Reads exactly `header_len` bytes, which is the header.
3. Takes `payload_len` from the header and reads exactly that many bytes.

Because each read has a known size, the receiver always knows where the message ends. In our client this is `recv_exact()`, which loops until the requested number of bytes has arrived.

Without a length, the receiver would need another way to find the end of the header. Each alternative has a drawback:

| Alternative | Problem |
|---|---|
| A delimiter such as a newline | The delimiter must never appear in the data. That is workable for JSON text, but the binary payload could contain it, so it would need escaping. |
| Parse JSON until the braces balance | The receiver has to parse incrementally and handle braces inside strings. A malformed header could make it read forever. |
| Close the connection to mark the end | Impossible here. The client must keep the connection open to read the reply after sending the request. |

A length prefix is simple and works for binary data. It also lets the server reject a bad header cheaply: it can refuse `header_len` over 1000 *before reading any of it*, and it checks `payload_len` against the 1 MiB limit before reading the payload. Our `read_reply()` does the same for replies, so a server that sends a huge or garbage length cannot make the client allocate memory or wait forever.

### Why exactly four bytes

Four bytes (an unsigned 32-bit integer) can describe up to about 4 GB. The header is limited to 1000 bytes, so two bytes would have been enough. Four is the usual choice because it is a standard, easy-to-parse width (`struct.pack(">I", n)`), leaves room to grow, and keeps the prefix aligned with common practice. The width must be fixed, because a variable-length length field would itself need framing.

### Why big-endian

A multi-byte number can be stored in two byte orders. For the length 57 (`0x39`):

- **Big-endian:** `00 00 00 39`. The most significant byte is first.
- **Little-endian:** `39 00 00 00`.

The protocol has to pick one, because the sender and receiver may run on different CPUs. Big-endian is also called **network byte order**, the convention used across internet protocols, and it reads naturally in a hex dump. The spec's Section 9 test vector confirms it: the 57-byte header is prefixed with `00 00 00 39`. A client that gets this wrong sends a length of `0x39000000` (about 956 million bytes). The server would reject it or wait for data that never comes. The spec lists this as the first common mistake, and our `check_framing_vector()` catches it at startup.

### Two related details

- **The length counts bytes, not characters.** The header is UTF-8, so a non-ASCII character takes more than one byte. `build_request()` measures the encoded bytes, not the Python string.
- **The length covers only the header.** It excludes itself and the payload. The payload has its own length, `payload_len`, inside the header, so the header can be read and checked before any large payload is accepted.

### In short

TCP delivers the bytes correctly but does not mark message boundaries. The four-byte big-endian length is the framing layer that lets both sides split the stream back into messages, and the fixed byte order lets any two machines agree on the number.


## Q4. Why AES-GCM instead of AES-CBC? What does GCM add for encrypting and authenticating files?

### Where the choice comes from

The choice was not made by our design. `crypto_message_spec_v2.md` (Section 5) fixes the format as AES-256-GCM with a 12-byte nonce, a 16-byte tag and no AAD, and the server decrypts only that format. The reasons below explain why GCM is a sound fit for this protocol.

### The core difference

- **CBC** provides **confidentiality only**. It hides the contents but cannot tell the receiver whether the ciphertext was changed.
- **GCM** is **authenticated encryption (AEAD)**. It encrypts and produces an authentication tag in a single operation. Decryption fails if any ciphertext byte, the nonce or the tag was altered, or if the key is wrong.

### Advantages of GCM for files

| Aspect | CBC | GCM |
|---|---|---|
| Integrity | None. A separate MAC is needed, and it must be combined correctly (encrypt-then-MAC, with a separate key). | Built in. A 16-byte tag covers the whole ciphertext. |
| Tampering | Modified ciphertext still decrypts. Flipping a bit in one block garbles that block and flips the same bit in the next plaintext block, which an attacker can exploit. | Any modification is detected, and decryption raises an error (`InvalidTag` in Python's `cryptography`). |
| Padding | Requires padding (such as PKCS#7) to a 16-byte multiple. Padding errors have enabled *padding-oracle attacks* when a system reveals whether padding was valid. | No padding. The ciphertext is exactly as long as the plaintext, so the file grows by only 28 bytes (nonce 12 + tag 16). |
| Parallelism | Encryption is sequential, because each block depends on the previous ciphertext block. | Built on counter mode, so blocks can be processed in parallel and the data can be streamed. |
| Misuse surface | Two separate pieces (cipher and MAC) that must be combined correctly. A single mistake can break security. | One call, one key. Python's `AESGCM(key).encrypt(nonce, data, None)` returns `ciphertext || tag` already combined. |

### How this shows up in our project

- **Corrupted or modified files are rejected.** Spec Section 4.3 lists "a file that was modified or corrupted" among the causes of the server's generic `error`. That happens because the GCM tag check fails. Our mock server does the same, and `test_faults.py` checks it by flipping the last byte of an encrypted file and expecting `error`.
- **No padding code to get wrong.** `aes_encrypt()` is just `nonce + AESGCM(key).encrypt(nonce, plaintext, None)`. The spec's size rule (plaintext + 28 bytes, and the 1,048,548-byte plaintext limit) follows directly from GCM adding no padding.
- **An empty file works.** GCM can encrypt zero bytes, producing a valid 28-byte file. CBC would need a full block of padding.
- **The round trip is its own check.** The AES workflow decrypts on the server and compares bytes. GCM guarantees a wrong key or damaged data fails loudly instead of returning garbage.

### Cautions that come with GCM

- **Never reuse a nonce with the same key.** This is GCM's biggest weakness. Reuse can reveal the XOR of two plaintexts and can let an attacker forge tags. Our client generates a fresh `os.urandom(12)` for every file, and the spec lists nonce reuse as a common mistake. Our keys are also single-use per run (R22), which makes random-nonce collisions practically impossible.
- **Verify before use.** Plaintext must never be used until the tag has been checked. `AESGCM.decrypt` does this, and returns nothing if the check fails.
- **Associated data is empty.** The spec uses no AAD, so details like the file name are not authenticated. Someone could swap an encrypted file for another one that was encrypted with the same key.
- **The tag proves "made with this key", not "made by this person".** The key is shared between the client and the server, so GCM gives integrity against outsiders, not proof of who sent a file.

### GCM versus the course HMAC

The two workflows protect different things:

- **AES-GCM** encrypts a file and authenticates the ciphertext in one step.
- **The course HMAC** authenticates a file that stays in plaintext, with no encryption.

The HMAC is a separate, hand-built construction (see Q1 and Q2). The GCM tag is part of a standard AEAD design.

### In short

CBC hides data but cannot detect tampering, needs padding, and leaves integrity to a separate MAC that must be combined correctly. GCM gives encryption and authentication in one operation, with no padding and a fixed 28-byte overhead. In exchange, it requires a fresh nonce for every file.


## Q5. Why must the inner hash be the 32-byte digest and not a 64-character hex string? What would `.hexdigest()` change?

### What the spec requires

Section 6 of `crypto_message_spec_v2.md` defines `HMAC = SHA-256( Ko || SHA-256( Ki || x ) )` and states: "The inner hash is the **32 raw bytes**, not hex text." In our code, `sha256()` returns `hashlib.sha256(data).digest()`, and `custom_hmac()` concatenates that value directly after `ko`.

### Two different things

SHA-256 produces 256 bits, which is 32 bytes. There are two ways to represent them:

| Form | Python | Length | Example start |
|---|---|---|---|
| Raw bytes | `.digest()` | 32 bytes | `05 00 1c 1f 52 …` |
| Hex text | `.hexdigest()` | 64 ASCII characters, which is 64 bytes when encoded | `"05001c1f52…"` |

The hex string is the **same value written out as text**. As input to a hash function it is a completely different byte sequence: each raw byte `0x05` becomes the two characters `'0'` and `'5'` (bytes `0x30 0x35`).

### Why it changes the result

SHA-256 hashes bytes and knows nothing about what they mean. The outer hash input is:

- **Correct:** `Ko` (32 bytes) followed by the 32 raw inner-digest bytes, 64 bytes in total.
- **With hex text:** `Ko` (32 bytes) followed by 64 ASCII characters, 96 bytes in total.

These inputs differ in length and in content. Because SHA-256 has the avalanche property (a tiny input change gives an unrelated output), the two results have nothing in common.

I computed both for the Section 9 vector (K = `00 01 … 1f`, x = `hello world`):

```
.digest()    ->  585c65e6deb8b876ed74222c5964060e707192df8ce9b91b6198de173fbfff2e   (matches the spec)
.hexdigest() ->  e02957ea45eabc6efbf1b9c0d20e3af6843b823c2b90df3d8d47e9cc1b30cf77   (wrong)
```

The hex-based version does not resemble the expected value at all, so the mistake cannot be spotted by comparing the first few characters.

### How the mistake would show up

- **In Python it doesn't fail loudly.** `ko + sha256(...).hexdigest()` raises `TypeError`, because `bytes` and `str` can't be added. The usual fix is to add `.encode()`, which then runs without any error and quietly produces the wrong HMAC.
- **Locally:** `check_hmac_vectors()` fails at startup, because the `hello world`, inner-hash and empty-file vectors would not match. The app then disables the HMAC workflow with an error banner.
- **Against the server:** the request would be well formed, so the server answers `verify_result` with `FAILED`, **not** an `error`. A wrong HMAC and a tampered file look the same to the server. This is why the self-check matters, and why the spec says to test against the vectors *before* touching the server.
- **Other wire problems:** the `hmac` field must be base64 of exactly 32 bytes. Sending the 64-character hex text as the final HMAC would not decode to 32 bytes, so the server would reply `error`. The inner hash is the same idea one step earlier: it must stay raw bytes inside the computation.

### Is hex text insecure?

Not on its own. It would be a *different* function, and a deterministic one, so it could still work as a MAC if both sides agreed on it. The problem is **interoperability**: the server computes the course construction with raw bytes. If the client and server disagree on even one byte of the hashed input, every verification fails. The spec is the single authority, and a custom MAC that doesn't follow it is simply incompatible, not "extra safe" or "less safe".

### The same rule applies elsewhere

Hash and MAC values stay as raw bytes everywhere inside the program. They are converted to text only at the edges: base64 for the JSON header and the `.hmac` / `.hmackey` files. Converting too early, or hashing a text form, is the same family of mistake the spec lists under "Hashing hex text instead of raw bytes for the inner hash".

### In short

The inner hash must be the 32 raw digest bytes because the construction is defined over bytes. `.hexdigest()` hashes 64 characters of text, which is a different input and gives an unrelated output (`e02957ea…` instead of `585c65e6…`). The server then answers `FAILED`, and our startup vector check catches the mistake first.
