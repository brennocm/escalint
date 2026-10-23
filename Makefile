# Every command the CI runs exists here, so a failure can be reproduced locally.
# Targets for later phases fail loudly instead of passing silently.

SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

GO          ?= go
PNPM        ?= pnpm
GOLANGCI    ?= golangci-lint
GOVULNCHECK ?= govulncheck

BIN_DIR  := bin
BINARY   := $(BIN_DIR)/escalint
WEB_DIR  := web
COVER_OUT := coverage.out

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell git log -1 --format=%cI 2>/dev/null || echo unknown)
PKG_BUILDINFO := github.com/brennocm/escalint/internal/buildinfo
LDFLAGS := -s -w -X $(PKG_BUILDINFO).Version=$(VERSION) -X $(PKG_BUILDINFO).Commit=$(COMMIT) -X $(PKG_BUILDINFO).Date=$(DATE)

# Tests never need the frontend (ADR 0002).
GO_TEST_FLAGS := -tags noui
GO_PKGS = $(shell $(GO) list $(GO_TEST_FLAGS) ./... | grep -v /tools/)

define not_yet
	@echo "make $@: not implemented yet ($(1))" >&2; exit 1
endef

.PHONY: help
help: ## List targets
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "} {printf "  %-18s %s\n", $$1, $$2}'

## ---- Go ----------------------------------------------------------------

.PHONY: build
build: ## Build the binary with the embedded UI (run web-build first)
	@test -f $(WEB_DIR)/dist/index.html || { echo "web/dist missing: run 'make web-build' or use 'make build-noui'" >&2; exit 1; }
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/escalint

.PHONY: build-noui
build-noui: ## Build the binary without the UI (no Node.js needed)
	CGO_ENABLED=0 $(GO) build -trimpath -tags noui -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/escalint

.PHONY: test
test: ## Run Go tests
	$(GO) test $(GO_TEST_FLAGS) ./...

.PHONY: test-race
test-race: ## Run Go tests with the race detector
	$(GO) test $(GO_TEST_FLAGS) -race ./...

.PHONY: cover
cover: ## Go coverage profile + HTML report
	$(GO) test $(GO_TEST_FLAGS) -race -covermode=atomic -coverprofile=$(COVER_OUT) $(GO_PKGS)
	$(GO) tool cover -html=$(COVER_OUT) -o coverage.html

.PHONY: cover-check
cover-check: cover ## Enforce per-package coverage targets (prints a Markdown table)
	$(GO) run ./tools/covercheck -profile $(COVER_OUT)

.PHONY: lint
lint: ## golangci-lint (includes gofumpt) and go vet
	$(GO) vet $(GO_TEST_FLAGS) ./...
	$(GOLANGCI) run ./...
	$(GOLANGCI) fmt --diff ./...

.PHONY: vuln
vuln: ## govulncheck
	$(GOVULNCHECK) -tags noui ./...

.PHONY: fuzz
fuzz: ## Fuzz every target for FUZZTIME (default 5m)
	$(MAKE) fuzz-run FUZZTIME=$${FUZZTIME:-5m}

.PHONY: fuzz-smoke
fuzz-smoke: ## Fuzz every target for 30 s
	$(MAKE) fuzz-run FUZZTIME=30s

# Go runs one fuzz target per invocation, so list them per package first.
# Minimization is capped: with the default (60 s per input) the large
# snapshot seeds stall the fuzzer at a handful of executions.
.PHONY: fuzz-run
fuzz-run:
	@for pkg in $(GO_PKGS); do \
	  for target in $$($(GO) test $(GO_TEST_FLAGS) -list '^Fuzz' $$pkg | grep '^Fuzz' || true); do \
	    echo "==> $$pkg $$target ($(FUZZTIME))"; \
	    $(GO) test $(GO_TEST_FLAGS) -run '^$$' -fuzz "^$$target\$$" -fuzztime $(FUZZTIME) -fuzzminimizetime 5s $$pkg || exit 1; \
	  done; \
	done

.PHONY: golden-update
golden-update: ## Rewrite golden files (review the diff before committing)
	$(GO) test $(GO_TEST_FLAGS) ./internal/contract/ ./internal/report/ -run Golden -update

.PHONY: gen
gen: ## Regenerate generated data (downloads the AWS service reference and ATT&CK)
	$(GO) generate ./internal/catalog/ ./internal/attack/ ./internal/detect/

# The catalog needs the network and changes with AWS, so it is not part of
# gen-check; the monthly catalog workflow (Phase 14) proposes updates.
.PHONY: gen-check
gen-check: gen-contract ## Fail if offline-generated files are stale
	git diff --exit-code -- web/src/contract/

.PHONY: gen-contract
gen-contract: ## Generate the TypeScript contract from the JSON Schema
	$(GO) run ./tools/gen-contract-ts -schema schema/analysis.v1.schema.json -out web/src/contract/analysis.ts

## ---- Web ---------------------------------------------------------------

.PHONY: web-install
web-install: ## Install frontend dependencies (frozen lockfile)
	cd $(WEB_DIR) && $(PNPM) install --frozen-lockfile

.PHONY: web-build
web-build: ## Build the frontend into web/dist
	cd $(WEB_DIR) && $(PNPM) build

.PHONY: web-lint
web-lint: ## ESLint, Prettier check and tsc
	cd $(WEB_DIR) && $(PNPM) lint && $(PNPM) format:check && $(PNPM) typecheck

.PHONY: web-test
web-test: ## Vitest with coverage
	cd $(WEB_DIR) && $(PNPM) test:coverage

.PHONY: web-e2e
web-e2e: ## Playwright E2E (Chromium, Firefox, WebKit)
	cd $(WEB_DIR) && $(PNPM) e2e

.PHONY: web-visual
web-visual: ## Visual regression inside the Playwright container
	$(call not_yet,visual baselines per view arrive in Phase 12 - ADR 0019)

.PHONY: web-visual-update
web-visual-update: ## Update visual baselines inside the Playwright container
	$(call not_yet,visual baselines per view arrive in Phase 12 - ADR 0019)

.PHONY: web-a11y
web-a11y: ## axe accessibility checks
	$(call not_yet,accessibility suite arrives in Phase 12)

.PHONY: web-perf
web-perf: ## Performance budgets with synthetic data
	$(call not_yet,performance suite arrives in Phase 12)

.PHONY: size
size: ## Bundle size budget
	$(call not_yet,size-limit arrives in Phase 11)

## ---- Distribution -------------------------------------------------------

.PHONY: demo
demo: ## Regenerate the CLI and UI demo recordings
	$(call not_yet,Phase 18)

.PHONY: pages
pages: ## Build the GitHub Pages demo
	$(call not_yet,Phase 13)

.PHONY: clean
clean: ## Remove build outputs
	rm -rf $(BIN_DIR) $(COVER_OUT) coverage.html $(WEB_DIR)/dist $(WEB_DIR)/coverage $(WEB_DIR)/playwright-report $(WEB_DIR)/test-results
