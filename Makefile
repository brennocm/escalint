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
	$(GO) test $(GO_TEST_FLAGS) -race -covermode=atomic -coverpkg=./... -coverprofile=$(COVER_OUT) $(GO_PKGS)
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

# Wall time and peak RSS of analyze/scan on synthetic accounts
# (docs/benchmarks.md). Needs GNU time; writes only to a temporary directory.
BENCH_SIZES ?= 1000 10000 50000
.PHONY: bench-cli
bench-cli: build-noui ## Time and peak memory of analyze and scan on 1k/10k/50k synthetic principals
	@tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	printf '| Principals | Command | Wall time (s) | Peak RSS (MB) | Output (MB) |\n| ---: | --- | ---: | ---: | ---: |\n'; \
	for n in $(BENCH_SIZES); do \
	  $(BINARY) synth --principals $$n --seed 7 --escalation-rate 0.02 -o $$tmp/s.snapshot.json; \
	  for cmd in "analyze" "scan -f json --fail-on none" "scan -f sarif --fail-on none"; do \
	    /usr/bin/time -f '%e %M' -o $$tmp/t $(BINARY) $$cmd $$tmp/s.snapshot.json --deterministic -q -o $$tmp/out; \
	    read -r wall rss < $$tmp/t; \
	    printf '| %s | `%s` | %s | %d | %d |\n' $$n "$${cmd%% --fail-on none}" $$wall $$((rss / 1024)) $$(( $$(stat -c %s $$tmp/out) / 1048576 )); \
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
gen-check: gen-contract gen-web-fixtures gen-docs ## Fail if offline-generated files are stale
	git diff --exit-code -- web/src/contract/ web/src/data/fixtures/ docs/coverage.md README.md

.PHONY: gen-docs
gen-docs: ## Regenerate docs/coverage.md and the README rule table from the rule registry
	$(GO) test $(GO_TEST_FLAGS) ./internal/rules/ -run 'TestCoverageDocUpToDate|TestReadmeRulesUpToDate' -update-docs

.PHONY: gen-web-fixtures
gen-web-fixtures: ## Regenerate the analysis.json fixtures of the web tests
	$(GO) run -tags noui ./cmd/escalint analyze examples/vulnerable-account/snapshot.json --config-file examples/vulnerable-account/.escalint.yaml --deterministic -o web/src/data/fixtures/vulnerable.analysis.json
	$(GO) run -tags noui ./cmd/escalint analyze examples/hardened-account/snapshot.json --config-file examples/hardened-account/.escalint.yaml --deterministic -o web/src/data/fixtures/hardened.analysis.json
	$(GO) run -tags noui ./cmd/escalint diff internal/rules/testdata/EL-PE-020/safe/snapshot.json internal/rules/testdata/EL-PE-020/vulnerable/snapshot.json -f analysis --fail-on none --deterministic -o web/src/data/fixtures/diff.analysis.json

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
web-visual: ## Visual regression (Chromium; CI runs it in the Playwright container, ADR 0019)
	cd $(WEB_DIR) && $(PNPM) build && $(PNPM) e2e:visual

.PHONY: web-visual-update
web-visual-update: ## Rewrite visual baselines (review the images before committing)
	cd $(WEB_DIR) && $(PNPM) build && $(PNPM) e2e:visual:update

.PHONY: web-a11y
web-a11y: ## axe accessibility checks (WCAG 2.2 AA, every view, both themes)
	cd $(WEB_DIR) && $(PNPM) build && $(PNPM) exec playwright test --project=chromium views

.PHONY: web-e2e-serve
web-e2e-serve: ## serve and report end to end against bin/escalint (run make web-build build first)
	cd $(WEB_DIR) && $(PNPM) e2e:serve

.PHONY: web-e2e-demo
web-e2e-demo: ## Pages demo end to end (run make demo first)
	cd $(WEB_DIR) && $(PNPM) e2e:demo

.PHONY: web-perf
web-perf: ## Performance budgets with synthetic data (10k principals)
	cd $(WEB_DIR) && $(PNPM) build && $(PNPM) e2e:perf

.PHONY: size
size: ## Bundle size budget
	cd web && pnpm build && pnpm size

## ---- Distribution -------------------------------------------------------

.PHONY: demo
demo: ## Build the GitHub Pages demo into web/dist-demo (synthetic data only)
	cd $(WEB_DIR) && $(PNPM) build:demo
	mkdir -p $(WEB_DIR)/dist-demo/data
	$(GO) run -tags noui ./cmd/escalint analyze examples/vulnerable-account/snapshot.json --config-file examples/vulnerable-account/.escalint.yaml --deterministic -o $(WEB_DIR)/dist-demo/data/vulnerable.json
	$(GO) run -tags noui ./cmd/escalint synth --principals 1000 --accounts 2 --seed 7 --escalation-rate 0.02 -o $(WEB_DIR)/dist-demo/data/synthetic-2k.snapshot.json
	$(GO) run -tags noui ./cmd/escalint analyze $(WEB_DIR)/dist-demo/data/synthetic-2k.snapshot.json --deterministic -o $(WEB_DIR)/dist-demo/data/synthetic-2k.json
	rm $(WEB_DIR)/dist-demo/data/synthetic-2k.snapshot.json

.PHONY: pages
pages: demo ## Build the GitHub Pages site (the demo) into web/dist-demo

## ---- README media ------------------------------------------------------
# Not part of `make demo` (the Pages build, which CI runs without vhs or
# ffmpeg). Requires vhs (with ttyd) and ffmpeg.
MEDIA_DIR := docs/media

.PHONY: demo-media
demo-media: demo-cli demo-video ## Regenerate the CLI GIF, UI video/GIF and view screenshots in docs/media

.PHONY: demo-cli
demo-cli: ## Record the CLI demo (demo.tape) into docs/media/cli.gif with vhs
	$(MAKE) build-noui VERSION=$$(git describe --tags --always 2>/dev/null || echo dev)
	PATH="$(CURDIR)/$(BIN_DIR):$$PATH" vhs demo.tape

.PHONY: demo-video
demo-video: web-build ## Record the UI walkthrough (MP4 + GIF) and one screenshot per view and theme
	cd $(WEB_DIR) && $(PNPM) media
	ffmpeg -loglevel error -y -i $(MEDIA_DIR)/ui.webm -c:v libx264 -preset slow -crf 30 -pix_fmt yuv420p -movflags +faststart -an $(MEDIA_DIR)/ui.mp4
	ffmpeg -loglevel error -y -i $(MEDIA_DIR)/ui.webm -vf "fps=8,scale=880:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=128:stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=4" $(MEDIA_DIR)/ui.gif
	rm -rf $(MEDIA_DIR)/ui.webm $(MEDIA_DIR)/.video

.PHONY: release-check
release-check: ## Validate .goreleaser.yaml
	goreleaser check

.PHONY: release-snapshot
release-snapshot: web-build ## Local GoReleaser build into dist/ (no image, signature, SBOM or publish)
	goreleaser release --snapshot --clean --skip=docker,sign,sbom,publish

.PHONY: docker
docker: ## Build the image from source (Dockerfile) as escalint:dev
	docker build -t escalint:dev --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg DATE=$(DATE) .

.PHONY: clean
clean: ## Remove build outputs
	rm -rf $(BIN_DIR) dist $(COVER_OUT) coverage.html $(WEB_DIR)/dist $(WEB_DIR)/dist-demo $(WEB_DIR)/coverage $(WEB_DIR)/playwright-report $(WEB_DIR)/test-results
