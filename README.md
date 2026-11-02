# muira

Gerenciador de segredos offline em linha de comando, escrito em Go.

*muira* vem de *muiraquitã*, um amuleto protetor amazônico.

> ⚠️ **Projeto de estudo. Não use para guardar senhas reais.**

## Sobre

O muira guarda segredos num arquivo local cifrado com uma senha mestra
(Argon2id + AES-256-GCM com *envelope encryption*). Mais do que o cofre em
si, o projeto demonstra **desenvolvimento assistido por LLM com travas
automáticas de qualidade**: a pessoa define especificação e critérios de
aceite, o agente implementa, as travas validam e a pessoa revisa e aprova
cada commit.

Status: Fase 1 (crypto) concluída; a próxima é a Fase 2 (storage). O
pacote `internal/crypto` está pronto: Argon2id, AES-256-GCM, AAD
length-prefixed e *envelope encryption*, validados contra vetores
oficiais (NIST CAVP e phc-winner-argon2), com 98% de cobertura, fuzz e
teste de mutação. Ainda não existe CLI utilizável. Veja o
[roadmap](docs/ROADMAP.md) e as [decisões de arquitetura](docs/adr/).

## Custo do desbloqueio

Desbloquear o cofre deriva a KEK com Argon2id nos parâmetros padrão da
[ADR 0002](docs/adr/0002-crypto-design.md) (`t=3`, `m=64 MiB`, `p=4`).
Esse custo é proposital: é o que torna lenta a força bruta contra um
arquivo de cofre roubado.

| Máquina | Tempo por derivação | Memória por derivação |
|---|---|---|
| AMD Ryzen 5 5600G (12 threads), Linux no WSL2, Go 1.27.3 | 46–51 ms | ~64 MiB |

Medido com
`go test -run='^$' -bench=DeriveKey -benchmem -count=5 ./internal/crypto`
em 2026-11-02 (5 rodadas, de 22 a 26 iterações cada).

## Modelo de ameaças

_A ser escrito na Fase 5._

## Desenvolvimento assistido por LLM

_A ser escrito na Fase 5._
