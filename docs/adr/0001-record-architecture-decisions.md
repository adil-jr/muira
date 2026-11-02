# 1. Record architecture decisions

- Status: Accepted
- Date: 2026-11-01

## Context

muira is built with an LLM coding agent under human review. Decisions made
in a chat session are lost when the session ends, and a future session (or
a reviewer) has no way to know why the code looks the way it does. We need a
durable, reviewable record of significant decisions.

## Decision

We record architecture decisions as Architecture Decision Records (ADRs), as
described by Michael Nygard in "Documenting Architecture Decisions" (2011).

- ADRs live in `docs/adr/`, named `NNNN-short-title.md`, numbered sequentially.
- Each ADR has: title, status, date, context, decision, consequences.
- Status is one of: Proposed, Accepted, Rejected, Deprecated, Superseded by NNNN.
- An agent may draft an ADR as Proposed; only the human moves it to Accepted.
- Accepted ADRs are not rewritten; a change of mind is a new ADR that
  supersedes the old one.
- Adding a dependency outside the allowed list (see `CLAUDE.md`) requires an ADR.

## Consequences

- Every phase closes with a check for new decisions that deserve an ADR.
- Reviewers can trace the reasoning behind the code without the chat history.
- Writing ADRs costs a little time per decision.
