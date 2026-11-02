# 2. Cryptographic design

- Status: **Proposed** (to be reviewed by the human before Phase 1)
- Date: 2026-11-01

## Context

muira stores secrets in a local file protected by a single master password.
We need a design that:

- resists offline brute force of the vault file;
- allows changing the master password without re-encrypting every record;
- detects tampering and record swapping;
- can evolve its on-disk format;
- is testable against official known-answer vectors, not against itself.

Only primitives from the Go standard library and `golang.org/x/crypto` are
allowed, and only inside `internal/crypto`.

## Decision

### Envelope encryption

```
master password ──Argon2id(salt, params)──▶ KEK (32 bytes)
crypto/rand ──────────────────────────────▶ DEK (32 bytes)
wrapped DEK  = AES-256-GCM(KEK, nonce, DEK,       AAD = format version ‖ KDF params)
record blob  = AES-256-GCM(DEK, nonce, plaintext, AAD = record ID)
```

- The **KEK** (key-encryption key) is derived from the master password with
  Argon2id and never stored.
- The **DEK** (data-encryption key) is 32 random bytes from `crypto/rand`,
  generated once at `init`, and stored only wrapped by the KEK.
- Records are encrypted with the DEK.
- **Password rotation** derives a new KEK (new salt) and re-wraps only the
  DEK. Records are untouched.
- **Password verification**: the password is correct if and only if the
  wrapped DEK decrypts (GCM tag verifies). There is no separate verifier hash,
  which would be one more offline-attack target and one more thing to keep in
  sync.

### Argon2id parameters

RFC 9106, section 4, second recommended option (for memory-constrained
environments):

| Parameter | Value |
|---|---|
| Iterations `t` | 3 |
| Memory `m` | 64 MiB (65536 KiB) |
| Parallelism `p` | 4 |
| Salt | 16 random bytes (`crypto/rand`), new on every rotation |
| Output | 32 bytes |

Implementation: `argon2.IDKey` from `golang.org/x/crypto/argon2` (Argon2
version 0x13).

The parameters and the salt are **written to the vault metadata** at `init`
and on every rotation, and are **always read from the metadata** when
unlocking. Production defaults are used only when creating new key material,
so the defaults can be raised later without breaking existing vaults.

### AES-256-GCM

- `crypto/aes` + `crypto/cipher.NewGCM`, standard 16-byte tag.
- A fresh **random 12-byte nonce** from `crypto/rand` for every encryption.
  NIST SP 800-38D limits random-nonce use to 2^32 encryptions per key, far
  beyond what a personal vault does; rotation of the DEK itself is out of
  scope for the MVP.
- **AAD for records**: the record ID, so a ciphertext copied onto another
  record fails to decrypt.
- **AAD for the wrapped DEK**: format version and the encoded KDF
  parameters (including the salt), so tampering with the metadata fails
  authentication instead of silently weakening the KDF.

### Blob format

Every encrypted blob starts with a format version byte:

```
version (1 byte) ‖ nonce (12 bytes) ‖ ciphertext ‖ GCM tag (16 bytes)
```

Version `0x01` is the format described here. Unknown versions are rejected
with an error that contains no key material. A future format change bumps the
byte and adds a migration path.

### Testability

- An unexported function takes the **nonce as an explicit argument**, so
  known-answer vectors can be checked byte for byte.
- The exported API **always** generates the nonce itself; callers can never
  supply one.
- Argon2 parameters are **injected** (a `Params` value). Under `go test
  -short`, tests use cheap parameters (e.g. `t=1, m=64 KiB, p=1`). The
  production default is a separate constant that tests never mutate; one
  non-short test asserts the default equals the table above.

### Test vectors (expected values never come from our own code)

Vectors are committed under `testdata/` with their source recorded next to
them.

**AES-256-GCM: NIST CAVP**
- Archive: <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip>
  (SHA-256 `f9fc479e134cde2980b3bb7cddbcb567b2cd96fd753835243ed067699f26a023`,
  downloaded 2026-11-01).
- Files: `gcmEncryptExtIV256.rsp` and `gcmDecrypt256.rsp`, sections
  `[Keylen = 256]`, `[IVlen = 96]`, `[Taglen = 128]`. The decrypt file
  includes `FAIL` cases, which must be rejected.

**Argon2id: reference implementation (phc-winner-argon2)**
- Repository: <https://github.com/P-H-C/phc-winner-argon2>, commit
  `f57e61e19229e23c4445b85494dbf7c07de721cb`, file `src/test.c`, the
  `Argon2id` block for version `0x13` (`hashtest(version, t, log2(m KiB), p,
  pwd, salt, hexref, mcfref, Argon2_id)`, 32-byte output). Note that `m` is
  given as a base-2 logarithm of KiB (16 → 65536 KiB).
- **Not usable**: the RFC 9106 section 5.3 vector and the repository's
  `kats/argon2id` file both set a `secret` (K) and `associated data` (X).
  `argon2.IDKey` does not expose those inputs, so those vectors cannot be
  reproduced through the API we use.

## Consequences

- Unlocking costs ~64 MiB and a noticeable fraction of a second by design;
  tests must inject cheap parameters to stay fast.
- Rotation is cheap and atomic (one metadata write).
- A corrupted or tampered metadata record makes the vault fail to unlock
  rather than open with weaker parameters.

### Known limits

- **Memory hygiene is best effort.** Secrets are `[]byte` and zeroed with
  `clear()` after use, but the Go runtime may copy memory (GC, stack growth,
  `string` conversions in third-party code). We do not promise that secrets
  never linger in memory or swap.
- **File mode 0600 has no effect on Windows**; access there relies on the
  user profile ACLs.
- **No protection against malware running as the same user** (keyloggers,
  memory readers, a modified binary). The threat model covers a stolen or
  copied vault file, not a compromised account.

## Open questions for review

1. Should the record AAD also bind the blob header (version byte), to rule
   out a future downgrade across format versions? Proposal: AAD =
   `version ‖ record ID`.
2. Should the record ID used as AAD be the user-visible name or an internal
   random ID (renaming a record would then not require re-encryption)?
