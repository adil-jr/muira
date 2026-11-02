# Test vector sources

Expected values in `internal/crypto` tests come only from these files,
never from running muira's own code (CLAUDE.md, rule 5; ADR 0002).
They were fetched and verified by `fetch-vectors.sh` (kept outside the
repository), which never executes downloaded content.

Retrieved: 2026-11-02

## AES-256-GCM: NIST CAVP

- Archive: <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip>
- Archive SHA-256: `f9fc479e134cde2980b3bb7cddbcb567b2cd96fd753835243ed067699f26a023`
- Extracted unchanged (`unzip -p`):

| File | SHA-256 |
|---|---|
| `nist-gcm/gcmEncryptExtIV256.rsp` | `4448b4998c3f58cd9f5542ddf7c573189a721ff3d3ac24cd5177bb4910a787f8` |
| `nist-gcm/gcmDecrypt256.rsp` | `ed318735a517d5a85c82d2846c23dcf56e57a352fb0f0a163d9e7617a7bd12ad` |

- The `.rsp` files keep their original CRLF line endings;
  `testdata/.gitattributes` (`* -text`) disables EOL conversion so the
  stored bytes match these hashes.

- Tests use only the sections `[Keylen = 256]`, `[IVlen = 96]`,
  `[Taglen = 128]`. `gcmDecrypt256.rsp` includes `FAIL` cases, which must be
  rejected.

## Argon2id: phc-winner-argon2 reference implementation

- Repository: <https://github.com/P-H-C/phc-winner-argon2>
- Commit: `f57e61e19229e23c4445b85494dbf7c07de721cb`
- File: `src/test.c`, from
  <https://raw.githubusercontent.com/P-H-C/phc-winner-argon2/f57e61e19229e23c4445b85494dbf7c07de721cb/src/test.c>
- Git blob id (`git hash-object`): `055c19a3603669f0b54ed8fbb37e62da3d06ab88`
- File SHA-256: `ec518844e823fb6a1bd38f79f2b5d1bbddf23f490c0a343c450aa8e3f5af5988`
- Extracted: the lines from `Test Argon2id version number` up to (not
  including) `/* Common error state tests */`, with the last preceding assignment
  being `version = ARGON2_VERSION_NUMBER;` (Argon2 v0x13). The block holds
  8 `hashtest(version, t, log2(m KiB), p, pwd, salt, hexref, mcfref,
  Argon2_id)` calls with 32-byte output.

| File | SHA-256 |
|---|---|
| `argon2/argon2id-v13.test.c.txt` | `b374a7727f6df13166dab66c864998c071c32f154d74248c2b3f616258e87314` |

Not usable: the RFC 9106 section 5.3 vector and `kats/argon2id` set a secret
(K) and associated data (X), which `argon2.IDKey` does not expose.

## License

- The NIST CAVP vectors are a work of the U.S. government and are not
  subject to copyright in the United States.
- phc-winner-argon2 is dual licensed under CC0 1.0 and Apache 2.0; the
  excerpt is redistributed under CC0.
