GO ?= go
PKGS ?= ./...
BIN ?= bin/agentbox
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
# The commit range scripts/check-dco.sh inspects.
DCO_BASE ?= origin/main

.PHONY: all
all: fmt vet test validate-examples

.PHONY: build
build:
	$(GO) build -trimpath -ldflags "-X main.version=$(VERSION)" -o $(BIN) ./cmd/agentbox

.PHONY: fmt
fmt:
	$(GO) fmt $(PKGS)

.PHONY: fmt-check
fmt-check:
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "these files are not gofmt-clean:"; echo "$$unformatted"; exit 1; \
	fi

.PHONY: tidy-check
tidy-check:
	$(GO) mod tidy -diff

.PHONY: vet
vet:
	$(GO) vet $(PKGS)

.PHONY: lint
lint:
	golangci-lint run

# The store tests need PostgreSQL: point AGENTBOX_TEST_POSTGRES_DSN at an
# empty database first; without it they skip. `make test-db` starts a
# throwaway PostgreSQL 16 for them (needs the postgresql-16 package).
# -p 1: the database tests of different packages share one database.
.PHONY: test
test:
	$(GO) test -race -count=1 -p 1 $(PKGS)

PGDATA ?= .pg
PGPORT ?= 55432
PGBIN ?= /usr/lib/postgresql/16/bin
.PHONY: test-db
test-db:
	@test -d $(PGDATA)/data || $(PGBIN)/initdb -D $(PGDATA)/data -U postgres -A trust >/dev/null
	@$(PGBIN)/pg_ctl -D $(PGDATA)/data -o "-k $(abspath $(PGDATA)) -p $(PGPORT) -c listen_addresses=" -l $(PGDATA)/log start >/dev/null
	@psql -h $(abspath $(PGDATA)) -p $(PGPORT) -U postgres -tc "SELECT 1 FROM pg_database WHERE datname = 'agentbox_test'" | grep -q 1 || \
		psql -h $(abspath $(PGDATA)) -p $(PGPORT) -U postgres -c "CREATE DATABASE agentbox_test" >/dev/null
	@echo "export AGENTBOX_TEST_POSTGRES_DSN='postgres://postgres@/agentbox_test?host=$(abspath $(PGDATA))&port=$(PGPORT)'"

.PHONY: test-db-stop
test-db-stop:
	@$(PGBIN)/pg_ctl -D $(PGDATA)/data stop >/dev/null

# F02: every example passes validation through the CLI, not only in tests.
.PHONY: validate-examples
validate-examples: build
	$(BIN) validate examples/v0/config/*.yaml
	$(BIN) validate --kind consent examples/v0/consent/*.json
	$(BIN) validate --kind grant examples/v0/grant/*.json
	$(BIN) validate --kind decision examples/v0/decision/*.json
	$(BIN) validate --kind approval examples/v0/approval/*.json

.PHONY: dco-check
dco-check:
	scripts/check-dco.sh $(DCO_BASE) HEAD

# Refuse, before they exist, commits that dco-check would refuse.
.PHONY: hooks
hooks:
	git config core.hooksPath scripts/hooks

# What CI runs, in the same order.
.PHONY: ci
ci: tidy-check fmt-check vet lint test validate-examples

.PHONY: clean
clean:
	rm -rf bin dist *.out *.cover
