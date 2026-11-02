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
- [ ] KDF Argon2id com parâmetros lidos dos metadados do cofre (nunca fixos no código na leitura)
- [ ] Seal/open AES-256-GCM com nonce aleatório de 96 bits por operação; variante interna recebe nonce explícito para os testes de resposta conhecida (KAT)
- [ ] Formato de envelope versionado (byte de versão no início), DEK embrulhada pela KEK, AAD conforme a ADR 0002
- [ ] Vetores oficiais em `testdata/`: NIST CAVP GCM (chave de 256 bits, IV de 96 bits) e Argon2id do phc-winner-argon2, com a fonte exata citada
- [ ] Parâmetros baratos de Argon2 injetados em `-short`; padrões de produção intocados
- [ ] Alvos de fuzz para o parsing do envelope e para o open, ativados no `make fuzz` e no nightly
- [ ] Cobertura ≥ 85% com `-race`; relatório de mutação revisado

## Fase 2 — storage (`feat/storage`)
- [ ] Repositório bbolt com os buckets `meta` e `records`
- [ ] Arquivo do banco criado com modo 0600
- [ ] O storage guarda apenas bytes opacos; não sabe nada de criptografia
- [ ] Testes usam `t.TempDir()`; passam com `-race`

## Fase 3 — vault (`feat/vault`)
- [ ] `init`, `unlock`, `add`, `get`, `list`, `delete`, `rotate`
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
