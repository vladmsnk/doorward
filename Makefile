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

.PHONY: test
test:
	$(GO) test -race -count=1 $(PKGS)

# F02: every example passes validation through the CLI, not only in tests.
.PHONY: validate-examples
validate-examples: build
	$(BIN) validate examples/v0/config/*.yaml
	$(BIN) validate --kind taskrequest examples/v0/taskrequest/*.json
	$(BIN) validate --kind grant examples/v0/grant/*.json
	$(BIN) validate --kind offer examples/v0/offer/*.json
	$(BIN) validate --kind decision examples/v0/decision/*.json
	$(BIN) validate --kind approval examples/v0/approval/*.json

.PHONY: dco-check
dco-check:
	scripts/check-dco.sh $(DCO_BASE) HEAD

# What CI runs, in the same order.
.PHONY: ci
ci: tidy-check fmt-check vet lint test validate-examples

.PHONY: clean
clean:
	rm -rf bin dist *.out *.cover
