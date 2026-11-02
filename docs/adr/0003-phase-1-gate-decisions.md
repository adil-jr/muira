# 3. Decisões de travas da Fase 1

- Status: **Aceita** (2026-11-02, pelo humano; as duas decisões já foram
  revisadas e aplicadas nos commits
  `chore(lint): restrict x/crypto to argon2` e
  `chore(guard): protect package testdata directories`)
- Data: 2026-11-02

## Contexto

Durante a Fase 1 (`internal/crypto`) apareceram duas lacunas nas travas:

1. A allowlist do depguard liberava o módulo `golang.org/x/crypto` inteiro.
   O `govulncheck` acusou o GO-2026-5932: o pacote `openpgp` desse módulo
   é inseguro por design, não tem manutenção e não tem versão corrigida. O
   nosso código não o usa, mas nada impedia que passasse a usar.
2. O padrão `testdata/` de `scripts/protected-paths.txt` só vale na raiz do
   repositório. Um caso de regressão do fuzzer
   (`internal/crypto/testdata/fuzz/…`) ou um arquivo golden das próximas
   fases podia ser commitado sem passar pelo hook nem pelo job `guard`, e
   esses arquivos também são valores esperados (regra 5 do `CLAUDE.md`).

## Decisão

### Depguard restrito a `golang.org/x/crypto/argon2`

A allowlist do depguard (`.golangci.yml`) troca `golang.org/x/crypto` por
`golang.org/x/crypto/argon2`, o único subpacote de que precisamos (o
AES-GCM vem da biblioteca padrão).

Antes, o import de `openpgp` só era barrado pelo staticcheck (SA1019,
pacote marcado como deprecated). Esse aviso some com um `//nolint`
justificado, que o nolintlint aceita, e não pega subpacotes que não estão
marcados como deprecated. Com a mudança, a allowlist passa a ser a trava
explícita.

### `testdata/` de pacote protegido

`scripts/protected-paths.txt` ganha `internal/testdata/`,
`internal/*/testdata`, `internal/*/testdata/*` e os mesmos três padrões
para `cmd/`. Assim fica protegido qualquer diretório `testdata` em qualquer
profundidade abaixo de `internal/` e `cmd/`, inclusive o próprio diretório
(para `rm`/`mv` dele). `.claude/hooks/test-hooks.sh` ganha 12 casos.

- **Padrões sem `/` final.** No `protected_match`, só um padrão sem `/`
  final é tratado como glob (e o `*` casa também `/`). Com `/` final, o
  padrão é um prefixo literal, e o `*` não funcionaria.
- **`.gitignore` descartado.** Ignorar esses diretórios esconderia
  justamente o caso de falha que precisa ser revisto.

## Consequências

- Usar outro subpacote do `x/crypto` exige mudar a allowlist (arquivo
  protegido) e uma nova ADR.
- Casos de regressão do fuzzer e arquivos golden das Fases 2 a 4 só entram
  por patch aplicado pelo humano.
- `rm -rf internal` e `rm -rf cmd` passam a ser bloqueados no hook local.
- **Lacuna conhecida:** `rm -rf internal/<pacote>` (ou `mv`) não é
  bloqueado pelo hook local. A checagem "diretório que contém caminho
  protegido" do `.claude/hooks/lib.sh` compara o padrão como texto, e
  `internal/*/testdata` não começa literalmente com `internal/<pacote>/`.
  O job `guard` do CI cobre o caso, porque compara cada arquivo do diff e
  pega a remoção de qualquer arquivo commitado.
