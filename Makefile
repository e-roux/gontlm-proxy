SHELL := /bin/bash
.SILENT:
.DEFAULT_GOAL := help

#------------------------------------------------------------------------------
# Configuration
#------------------------------------------------------------------------------

GO            := go
GOLANGCI_LINT := golangci-lint

BINARY_NAME   := gontlm-proxy
OUTPUT_DIR    := build
VERSION       ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME    := $(shell date -u '+%Y-%m-%d_%H:%M:%S')

LDFLAGS := \
	-X github.com/bdwyertech/gontlm-proxy/cmd.GitCommit=$(shell git rev-parse --short HEAD 2>/dev/null || echo dev) \
	-X github.com/bdwyertech/gontlm-proxy/cmd.ReleaseVer=$(VERSION) \
	-X github.com/bdwyertech/gontlm-proxy/cmd.ReleaseDate=$(BUILD_TIME)

#------------------------------------------------------------------------------
# Build
#------------------------------------------------------------------------------

HOST_OS       := $(shell uname -s)
INSTALL_DIR   ?= $(HOME)/.local/bin
PLIST_LABEL   := com.user.gontlm-proxy
PLIST_TMPL    := contrib/macos/$(PLIST_LABEL).plist.tmpl
LAUNCHAGENTS  := $(HOME)/Library/LaunchAgents
PLIST_DEST    := $(LAUNCHAGENTS)/$(PLIST_LABEL).plist

#------------------------------------------------------------------------------
# Phony Targets
#------------------------------------------------------------------------------

.PHONY: help sync fmt lint typecheck check qa clean distclean
.PHONY: test test.unit test.integration test.e2e test.watch build install install.launchagent
build: $(OUTPUT_DIR)/$(BINARY_NAME)
install: $(INSTALL_DIR)/$(BINARY_NAME)
install.launchagent: $(PLIST_DEST)

#------------------------------------------------------------------------------
# High-Level Targets
#------------------------------------------------------------------------------

check: fmt lint typecheck
qa: check test
test: test.unit

#------------------------------------------------------------------------------
# Dependencies
#------------------------------------------------------------------------------

sync:
	$(GO) mod vendor

#------------------------------------------------------------------------------
# Code Quality
#------------------------------------------------------------------------------

fmt:
	$(GO) fmt ./...

lint:
	if command -v $(GOLANGCI_LINT) &>/dev/null; then \
		$(GOLANGCI_LINT) run --fix ./...; \
	else \
		$(GO) vet ./...; \
	fi

typecheck:
	$(GO) vet ./...

#------------------------------------------------------------------------------
# Testing
#------------------------------------------------------------------------------

test.unit:
	$(GO) test -mod=vendor -v -short -race ./...

test.integration:
	$(GO) test -mod=vendor -v -race ./...

test.e2e:
	echo "No e2e tests defined"

test.watch:
	which air &>/dev/null || $(GO) install github.com/air-verse/air@latest
	air --build.cmd "$(GO) test -mod=vendor ./..." --build.bin ""

#------------------------------------------------------------------------------
# Build
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# Build
#------------------------------------------------------------------------------

# All Go source files — used to detect when a rebuild is needed.
GO_SOURCES := $(shell find . -path ./vendor -prune -o -name '*.go' -print)

$(OUTPUT_DIR)/$(BINARY_NAME): $(GO_SOURCES)
	mkdir -p $(OUTPUT_DIR)
	$(GO) build -mod=vendor -trimpath \
		-ldflags "$(LDFLAGS)" \
		-o $@ \
		.

$(INSTALL_DIR)/$(BINARY_NAME): $(OUTPUT_DIR)/$(BINARY_NAME)
	mkdir -p $(INSTALL_DIR)
	install -m 0755 $< $@
	echo "Installed $(BINARY_NAME) -> $@"
ifeq ($(HOST_OS),Darwin)
	$(MAKE) install.launchagent
endif

$(PLIST_DEST):
	mkdir -p "$(LAUNCHAGENTS)" "$(HOME)/Library/Application Support/gontlm"
	sed \
		-e 's|{{HOME}}|$(HOME)|g' \
		-e 's|{{INSTALL_DIR}}|$(INSTALL_DIR)|g' \
		$(PLIST_TMPL) > "$@"
	echo "Installed LaunchAgent -> $@"
	echo "Edit $@ to set GONTLM_PROXY and credentials, then:"
	echo "  launchctl load $@"

#------------------------------------------------------------------------------
# Cleanup
#------------------------------------------------------------------------------

clean:
	rm -rf $(OUTPUT_DIR)
	$(GO) clean
	$(GO) clean -testcache

distclean: clean
	rm -f coverage.out coverage.html

#------------------------------------------------------------------------------
# Help
#------------------------------------------------------------------------------

help:
	printf "\033[36m"
	printf "                    _   _           \n"
	printf "  __ _  ___  _ __  | |_| |_ __ ___  \n"
	printf " / _' |/ _ \| '_ \ | __| | '_ ' _ \ \n"
	printf "| (_| | (_) | | | || |_| | | | | | |\n"
	printf " \__, |\___/|_| |_| \__|_|_| |_| |_|\n"
	printf " |___/  proxy                         \n"
	printf "\033[0m\n"
	printf "Usage: make [target]\n\n"
	printf "\033[1;35mSetup:\033[0m\n"
	printf "  sync             - Restore vendor dependencies\n"
	printf "\n"
	printf "\033[1;35mDevelopment:\033[0m\n"
	printf "  fmt              - Format code (go fmt)\n"
	printf "  lint             - Lint and auto-fix (golangci-lint or go vet)\n"
	printf "  typecheck        - Type validation (go vet)\n"
	printf "  check            - fmt + lint + typecheck\n"
	printf "  qa               - check + test (quality gate)\n"
	printf "\n"
	printf "\033[1;35mTesting:\033[0m\n"
	printf "  test             - Run all tests\n"
	printf "  test.unit        - Unit tests only (-short -race)\n"
	printf "  test.integration - All tests including integration\n"
	printf "  test.e2e         - End-to-end tests\n"
	printf "\n"
	printf "\033[1;35mBuild:\033[0m\n"
	printf "  build                - Build binary to build/\n"
	printf "  install              - Build, install binary, and install LaunchAgent on macOS\n"
	printf "  install.launchagent  - Install LaunchAgent plist (macOS only, skips if exists)\n"
	printf "\n"
	printf "\033[1;35mCleanup:\033[0m\n"
	printf "  clean            - Remove build artifacts\n"
	printf "  distclean        - Deep clean\n"
