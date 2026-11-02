# CLAUDE.md — muira

Offline secrets manager (Go CLI), built as LLM-assisted development behind
automated quality gates. The human writes specs and acceptance criteria and
approves every commit; you implement; the gates validate.

## Commands (always through the Makefile; tools are pinned in mise.toml)
- `make tools` install pinned tools (`mise install`)
- `make build` · `make test` (race) · `make test-short` · `make cover` (85% floor)
- `make lint` · `make fmt-check` · `make lint-scripts` (shellcheck + actionlint)
- `make vuln` (govulncheck) · `make fuzz` · `make mutation` (gremlins)
- Run tools ad hoc as `mise exec -- <tool>`; never install other versions.

## Package map and dependency rules
```
cmd/muira/        Cobra CLI. The ONLY place that prints to the terminal.
internal/vault/   Domain rules: init, unlock, add, get, list, delete, rotate.
internal/crypto/  Argon2id KDF, AES-256-GCM, envelope. ONLY importer of crypto/*.
internal/storage/ bbolt repository. Knows nothing about cryptography.
testdata/         Official test vectors (protected).
docs/adr/         Architecture decision records.
```
- `cmd` → `vault` → (`crypto`, `storage`). `cmd` never imports `crypto`/`storage`.
- `crypto` and `storage` never import each other. Enforced by depguard.
- Allowed modules: stdlib, `golang.org/x/crypto`, `golang.org/x/term`,
  `go.etcd.io/bbolt`, `github.com/spf13/cobra`. Anything else needs an ADR
  and human approval.

## Git workflow
- One branch per phase: `chore/foundation`, `feat/crypto`, `feat/storage`,
  `feat/vault`, `feat/cli`, `chore/release`.
- Never commit to `main`, never merge, never push unless the human asks.
- Conventional Commits in English (`feat(crypto): ...`, `test(storage): ...`).
- Small commits; each one builds, lints and passes tests.
- Before every commit show: changed files, diff summary, proposed message.
  Wait for explicit approval.
- Commit messages: write the message to a file in the session scratchpad
  with the Write tool and run `git commit -F <file>`. Never `-m`, never a
  heredoc (the Bash guard parses raw command text).

## Non-negotiable rules
1. Never log, print or put in an error: password, key, DEK, salt + password,
   nonce or plaintext.
2. Crypto only with Argon2id (`x/crypto/argon2`) and AES-256-GCM
   (`crypto/cipher`). Randomness only from `crypto/rand`. No homemade crypto.
3. Secrets travel as `[]byte`, never `string`. Zero them with `clear()` after
   use, best effort (the Go GC may copy; do not promise more than that).
4. Every `internal/` package needs tests passing with `-race` before the CLI
   uses it.
5. Expected values in crypto tests come from an official external source in
   `testdata/`, NEVER from running our own code.
6. Never bypass a gate: no `--no-verify`, `LEFTHOOK=0`, `core.hooksPath`
   changes, `//nolint` without a specific linter and explanation, loosened
   lint config, or deleted/weakened tests. If a gate blocks you, stop and
   explain why to the human.

## Protected files (see scripts/protected-paths.txt)
`.golangci.*`, `lefthook*`, `mise.toml` (and mise overrides), `Makefile`,
`scripts/`, `.github/`, `.claude/`, `testdata/`, `CLAUDE.md`. Claude Code
hooks block edits to them; `go.mod`/`go.sum`/`go.work` require confirmation.
Only the human edits protected files: propose a diff and let them apply it.
The Bash hook is best effort; the real gate is CI (`guard` job + branch
protection).

## Language
Code, comments, commits, ADRs and this file in English. README in Brazilian
Portuguese. Talk to the human in Brazilian Portuguese.

## Closing a phase
Update `docs/ROADMAP.md` (tick acceptance criteria) and propose an ADR in
`docs/adr/` for every new decision made during the phase.
