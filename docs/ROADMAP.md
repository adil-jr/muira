# Roadmap

Cada fase vive na sua própria branch e só é encerrada quando todos os
critérios de aceite estão marcados. Ao encerrar uma fase, atualize este
arquivo e registre as novas decisões como ADRs em `docs/adr/`.

## Fase 0 — fundação (`chore/foundation`)
- [x] Módulo Go, estrutura de pacotes, Makefile, versões das ferramentas fixadas em `mise.toml`
- [x] golangci-lint v2 com regras de camadas em depguard/forbidigo, comprovadamente falhando em violações
- [x] Lefthook pre-commit / commit-msg / pre-push
- [x] Hooks do Claude Code protegendo os arquivos das travas e bloqueando o contorno das travas
- [x] CI (lint, testes + piso de cobertura, govulncheck, shellcheck, actionlint, guard), nightly, Dependabot, CODEOWNERS
- [x] CLAUDE.md, ADR 0001, ADR 0002 (Proposta), esqueleto do README

## Fase 1 — preparação (`chore/phase-1-prep`)
- [x] ROADMAP, ADR 0001 e ADR 0002 traduzidos para pt-BR, sem mudança de conteúdo; regra de idioma no `CLAUDE.md`
- [x] Falso positivo do guard-bash com corpo de heredoc e argumento de `-m`/`-F`: **avaliado e rejeitado**. Com a regra de commit via arquivo (`git commit -F <arquivo>`), o falso positivo das mensagens não acontece mais, e a correção acrescentava ~350 linhas de parser em bash a uma trava de segurança: mais superfície de bug e código que o humano não consegue revisar linha a linha, o que quebra a regra de que ele revisa tudo o que entra nos arquivos protegidos. Decisão de custo/benefício.
- [x] `mise.lock` commitado e protegido (`scripts/protected-paths.txt`; `mise lock` e `mise upgrade` bloqueados no guard-bash), `PINNED_MISE_VERSION` em 2026.10.25 e CI instalando com `mise install --locked`
- [x] `locked = true` no `mise.toml`: **avaliado e não adotado**. A investigação (mise 2026.10.25, HOME falso com ferramentas globais fora do lock) mostrou:
  - com `locked = true` no projeto, `mise exec` e o lefthook funcionam com avisos, mas `mise install` (e portanto `make tools`) falha em quem tem ferramentas globais fora do lock;
  - o único jeito oficial de restringir o modo locked às ferramentas do projeto é o `locked_scopes`, que só vale na config global do usuário; o projeto não pode exigir config pessoal de quem clona;
  - o CI já instala com `--locked`, porque a `mise-action` o acrescenta quando existe `mise.lock`;
  - o risco local, um `mise exec`/`mise install` regravar o `mise.lock` quando o `mise.toml` muda sem `mise lock`, fica coberto: o `mise.toml` é protegido, a regravação aparece no `git status` e o CI pega (job `guard` e `--locked`).

### Limitação conhecida: guard-bash de melhor esforço
O guard-bash analisa o texto cru do comando, então gera falsos positivos, por exemplo:
- padrões de `grep`/`sed` que contêm um comando bloqueado (`grep 'mise use'`) ou um redirecionamento para caminho protegido (`'> Makefile'`);
- `mv x .` e outros caminhos relativos: o hook não conhece o diretório atual (cwd) e resolve `.` contra a raiz do projeto;
- corpo de heredoc e argumento de `-m` que citam comandos bloqueados.

Contorno legítimo, só quando o alvo não é protegido: usar as ferramentas Read/Write em vez do shell, ou caminho absoluto. Mensagens de commit vão sempre por arquivo. A trava real continua sendo o CI (job `guard` + proteção da branch).

## Fase 1 — crypto (`feat/crypto`)
- [x] ADR 0002 revisada e movida para Aceita
- [x] KDF Argon2id com parâmetros lidos dos metadados do cofre (nunca fixos no código na leitura). No `internal/crypto`, `DeriveKey`, `WrapDEK` e `UnwrapDEK` recebem `Params` e os validam a cada uso; `DefaultParams()` só serve para material de chave novo. A leitura dos metadados em si é do vault (Fase 3)
- [x] Seal/open AES-256-GCM com nonce aleatório de 96 bits por operação; variante interna recebe nonce explícito para os testes de resposta conhecida (KAT)
- [x] Formato de envelope versionado (byte de versão no início), DEK embrulhada pela KEK, AAD conforme a ADR 0002
- [x] Vetores oficiais em `testdata/`: NIST CAVP GCM (chave de 256 bits, IV de 96 bits) e Argon2id do phc-winner-argon2, com a fonte exata citada
- [x] Parâmetros baratos de Argon2 injetados em `-short`; padrões de produção intocados
- [x] Alvos de fuzz para o parsing do envelope e para o open, ativados no `make fuzz` e no nightly: `FuzzOpen` (cobre também o parsing do envelope), `FuzzAAD` e `FuzzRoundTrip`, 60 s por alvo sem falhas
- [x] Cobertura ≥ 85% com `-race`; relatório de mutação revisado:
  - cobertura de 98,0%;
  - mutação somando gremlins e uma passada manual: 47 mortos, 2 vivos justificados e 1 não viável, eficácia de 95,9%;
  - os 22 mutantes que o gremlins não executa (condições de `case` de `switch` e a soma do `Overhead`) foram aplicados à mão.
- [x] Restrição do depguard: de `golang.org/x/crypto` passa a valer só `golang.org/x/crypto/argon2`. O módulo também traz o `openpgp`, inseguro e sem manutenção (GO-2026-5932, sem correção). Antes, ele só era barrado pelo staticcheck (SA1019), que um `//nolint` justificado silenciaria (ADR 0003)
- [x] `testdata/` de pacote protegido em qualquer profundidade abaixo de `internal/` e `cmd/` (`scripts/protected-paths.txt`, com 12 casos novos no `test-hooks.sh`): casos de regressão do fuzzer e arquivos golden também são valores esperados (regra 5). Ignorar no `.gitignore` foi descartado, porque esconderia um caso de falha. Lacuna conhecida: `rm -rf internal/<pacote>` não é bloqueado pelo hook local, só pelo job `guard` do CI (ADR 0003)

## Fase 2 — storage (`feat/storage`)
- [ ] Repositório bbolt com os buckets `meta` e `records`
- [ ] Arquivo do banco criado com modo 0600
- [ ] O storage guarda apenas bytes opacos; não sabe nada de criptografia
- [ ] Testes usam `t.TempDir()`; passam com `-race`

## Fase 3 — vault (`feat/vault`)
- [ ] `init`, `unlock`, `add`, `get`, `list`, `delete`, `rotate`
- [ ] Parâmetros do Argon2id e salt lidos dos metadados do cofre a cada desbloqueio (nunca `DefaultParams()` na leitura); `ValidateNew` no `init` e na rotação
- [ ] Tipo `Secret` que mantém os valores como `[]byte` e os zera (melhor esforço)
- [ ] Senha errada detectada pela falha ao decifrar a DEK, não por um hash armazenado
- [ ] A rotação recifra apenas a DEK
- [ ] Cobertura ≥ 85% com `-race`

## Fase 4 — cli (`feat/cli`)
- [ ] Comandos Cobra mapeando 1:1 as operações do vault
- [ ] Senha lida com `x/term` (sem eco); nunca aceita como flag
- [ ] Erros impressos sem material secreto
- [ ] Testes ponta a ponta do binário contra um cofre temporário

## Fase 5 — release (`chore/release`)
- [ ] Configuração do GoReleaser com checksums SHA-256
- [ ] README com modelo de ameaças e o fluxo de desenvolvimento assistido por LLM

## v2 — fora do escopo do MVP
- [ ] Log de auditoria com `log/slog`
- [ ] Telemetria de diagnóstico (local, opt-in)
- [ ] Cópia para a área de transferência com limpeza automática
- [ ] TUI
- [ ] Índice cego com HMAC para buscar registros pelo nome sem decifrar todos (ADR 0002)
- [ ] Re-key da DEK: gerar uma DEK nova e recifrar todos os registros (ADR 0002)
