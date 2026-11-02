# 1. Registrar decisões de arquitetura

- Status: Aceita
- Data: 2026-11-01
- Idioma: tradução fiel do original em inglês (2026-11-02), sem mudança de conteúdo

## Contexto

O muira é construído com um agente de programação baseado em LLM, sob revisão
humana. Decisões tomadas numa sessão de chat se perdem quando a sessão
termina, e uma sessão futura (ou um revisor) não tem como saber por que o
código é como é. Precisamos de um registro durável e revisável das decisões
significativas.

## Decisão

Registramos as decisões de arquitetura como Architecture Decision Records
(ADRs), conforme descrito por Michael Nygard em "Documenting Architecture
Decisions" (2011).

- As ADRs ficam em `docs/adr/`, com nome `NNNN-titulo-curto.md`, numeradas em sequência.
- Cada ADR tem: título, status, data, contexto, decisão, consequências.
- O status é um destes: Proposta, Aceita, Rejeitada, Obsoleta, Substituída por NNNN.
- Um agente pode redigir uma ADR como Proposta; só o humano a move para Aceita.
- ADRs aceitas não são reescritas; uma mudança de ideia é uma nova ADR que
  substitui a antiga.
- Adicionar uma dependência fora da lista permitida (veja `CLAUDE.md`) exige uma ADR.

## Consequências

- Toda fase termina com uma verificação de novas decisões que merecem uma ADR.
- Revisores conseguem rastrear o raciocínio por trás do código sem o histórico do chat.
- Escrever ADRs custa um pouco de tempo por decisão.
