# Roadmap

Each phase lives on its own branch and is closed only when every acceptance
criterion is checked. When closing a phase, update this file and record new
decisions as ADRs in `docs/adr/`.

## Phase 0 — foundation (`chore/foundation`)
- [x] Go module, package layout, Makefile, tool versions pinned in `mise.toml`
- [x] golangci-lint v2 with depguard/forbidigo layering rules, proven to fail on violations
- [x] Lefthook pre-commit / commit-msg / pre-push
- [x] Claude Code hooks protecting gate files and blocking gate bypasses
- [x] CI (lint, test + coverage floor, govulncheck, shellcheck, actionlint, guard), nightly, Dependabot, CODEOWNERS
- [x] CLAUDE.md, ADR 0001, ADR 0002 (Proposed), README skeleton

## Phase 1 — crypto (`feat/crypto`)
- [ ] ADR 0002 reviewed and moved to Accepted
- [ ] Argon2id KDF with parameters taken from vault metadata (never hardcoded on read)
- [ ] AES-256-GCM seal/open with a random 96-bit nonce per operation; internal variant takes an explicit nonce for known-answer tests
- [ ] Versioned envelope format (leading version byte), DEK wrapped by KEK, AAD as specified in ADR 0002
- [ ] Official vectors in `testdata/`: NIST CAVP GCM (256-bit key, 96-bit IV) and phc-winner-argon2 Argon2id, with exact source cited
- [ ] Cheap Argon2 parameters injected under `-short`; production defaults untouched
- [ ] Fuzz targets for envelope parsing and open, enabled in `make fuzz` and nightly
- [ ] Coverage ≥ 85% with `-race`; mutation report reviewed

## Phase 2 — storage (`feat/storage`)
- [ ] bbolt repository with `meta` and `records` buckets
- [ ] Database file created with mode 0600
- [ ] Storage stores opaque bytes only; no knowledge of cryptography
- [ ] Tests use `t.TempDir()`; pass with `-race`

## Phase 3 — vault (`feat/vault`)
- [ ] `init`, `unlock`, `add`, `get`, `list`, `delete`, `rotate`
- [ ] `Secret` type that keeps values as `[]byte` and zeroes them (best effort)
- [ ] Wrong password detected by DEK decryption failure, not a stored hash
- [ ] Rotation re-encrypts only the DEK
- [ ] Coverage ≥ 85% with `-race`

## Phase 4 — cli (`feat/cli`)
- [ ] Cobra commands mapping 1:1 to vault operations
- [ ] Password read with `x/term` (no echo); never accepted as a flag
- [ ] Errors printed without secret material
- [ ] End-to-end tests of the binary against a temporary vault

## Phase 5 — release (`chore/release`)
- [ ] GoReleaser config with SHA-256 checksums
- [ ] README with threat model and the LLM-assisted development workflow

## v2 — out of MVP scope
- [ ] Audit log with `log/slog`
- [ ] Diagnostic telemetry (local, opt-in)
- [ ] Clipboard copy with automatic clearing
- [ ] TUI
