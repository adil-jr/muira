# Every tool runs through `mise exec --` so versions always come from
# mise.toml, even in non-interactive shells (git hooks, CI) where
# `mise activate` is not loaded. Protected file: humans edit it.

MISE    := mise exec --
GO      := $(MISE) go
BIN_DIR := bin
PKGS    := ./...

# Fuzz targets as <package>:<FuzzFunc>, one per entry. Enabled in Phase 1.
FUZZ_TARGETS ?=
# e.g. FUZZ_TARGETS := ./internal/crypto:FuzzOpen ./internal/crypto:FuzzParseEnvelope
FUZZTIME ?= 60s

# Packages under mutation testing.
MUTATION_PKGS ?= ./internal/crypto
# Extra gremlins flags, e.g. MUTATION_FLAGS="-o gremlins-report.json" in CI.
MUTATION_FLAGS ?=

.DEFAULT_GOAL := help

.PHONY: help
help: ## List available targets
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-14s %s\n", $$1, $$2}'

.PHONY: tools
tools: ## Install every pinned tool from mise.toml
	mise install

.PHONY: build
build: ## Build the muira binary into bin/
	$(GO) build -trimpath -o $(BIN_DIR)/muira ./cmd/muira

.PHONY: test
test: ## Run all tests with the race detector
	$(GO) test -race $(PKGS)

.PHONY: test-short
test-short: ## Run fast tests only (-short)
	$(GO) test -short $(PKGS)

.PHONY: cover
cover: ## Run tests with coverage and enforce the coverage floor
	$(GO) test -race -coverprofile=coverage.out $(PKGS)
	$(MISE) ./scripts/coverage-floor.sh coverage.out

.PHONY: fmt-check
fmt-check: ## Fail if any Go file is not gofumpt/goimports formatted
	$(MISE) golangci-lint fmt --diff

.PHONY: lint
lint: ## Run golangci-lint on the whole module
	$(MISE) golangci-lint run $(PKGS)

.PHONY: lint-scripts
lint-scripts: ## Lint shell scripts (shellcheck) and workflows (actionlint)
	find scripts .claude/hooks -type f -name '*.sh' -print0 2>/dev/null | xargs -0 -r $(MISE) shellcheck --severity=style
	@if [ -d .github/workflows ]; then $(MISE) actionlint; else echo "actionlint: no workflows yet"; fi

.PHONY: test-hooks
test-hooks: ## Run the Claude Code guard hook regression suite
	./.claude/hooks/test-hooks.sh

.PHONY: fuzz
fuzz: ## Run each fuzz target for FUZZTIME
	@if [ -z "$(strip $(FUZZ_TARGETS))" ]; then echo "fuzz: no targets configured yet (Phase 1)"; exit 0; fi
	@set -e; for t in $(FUZZ_TARGETS); do \
		pkg=$${t%%:*}; fn=$${t##*:}; \
		echo "==> $$pkg $$fn ($(FUZZTIME))"; \
		$(GO) test -run='^$$' -fuzz="^$$fn$$" -fuzztime=$(FUZZTIME) "$$pkg"; \
	done

.PHONY: vuln
vuln: ## Scan for known vulnerabilities with govulncheck
	$(MISE) govulncheck $(PKGS)

.PHONY: mutation
mutation: ## Run mutation tests (gremlins) on MUTATION_PKGS
	@set -e; for p in $(MUTATION_PKGS); do \
		echo "==> gremlins $$p"; \
		$(MISE) gremlins unleash $(MUTATION_FLAGS) "$$p"; \
	done

.PHONY: clean
clean: ## Remove build and coverage artifacts
	rm -rf $(BIN_DIR) coverage.out
