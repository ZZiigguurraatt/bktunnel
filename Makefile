## bktunnel — Makefile (builds the Go implementation)
##
## Run from the repo root. The Go module lives in go/; recipes step into it,
## with absolute output paths, so `make` works from the top of the tree.

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is
# set). Errors are swallowed so `make docker-build` stays quiet on a host with
# no Go installed (GOBIN is only used by the local install targets).
ifeq (,$(shell go env GOBIN 2>/dev/null))
GOBIN := $(shell go env GOPATH 2>/dev/null)/bin
else
GOBIN := $(shell go env GOBIN 2>/dev/null)
endif

# Build output goes into build/. Binaries land under build/bin/ (native
# at build/bin/bktunnel, cross-compiled under build/bin/<target>/bktunnel) and
# .deb packages land under build/packages/.
BUILD_DIR ?= $(shell pwd)/build
BIN_DIR   := $(BUILD_DIR)/bin
PKG_DIR   := $(BUILD_DIR)/packages
$(BUILD_DIR):
	mkdir -p "$(BIN_DIR)"

# GO steps into the go/ module before invoking the toolchain; NATIVE etc. are
# absolute so the `cd go` doesn't affect where the binary lands.
GO     := cd go &&
PKG    := ./cmd/bktunnel
NATIVE := $(BIN_DIR)/bktunnel
# Cross-compile outputs go under build/bin/<target>/bktunnel so the binary
# name stays `bktunnel` and the parent directory encodes the target —
# cleaner than a `bktunnel-<target>` suffix.
AMD64 := $(BIN_DIR)/amd64/bktunnel
ARM64 := $(BIN_DIR)/arm64/bktunnel
ARMV7 := $(BIN_DIR)/armv7/bktunnel
ARMV6 := $(BIN_DIR)/armv6/bktunnel
DARWIN_AMD64 := $(BIN_DIR)/darwin-amd64/bktunnel
DARWIN_ARM64 := $(BIN_DIR)/darwin-arm64/bktunnel

# Install locations.
#   USER_BIN defaults to whatever `go env GOBIN` (or GOPATH/bin) reports —
#   i.e. the same directory `go install` would drop binaries into. Override
#   if you want elsewhere, e.g. USER_BIN=$HOME/bin.
USER_BIN ?= $(GOBIN)
SYSTEM_BIN ?= /usr/local/bin

.PHONY: all
all: build

##@ General

# `make help` auto-generates a categorised list of targets by scanning for
# lines of the form `target: ## description` and `##@ category` headers.
.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Build

# Build targets are .PHONY because `go build` already has a content-aware
# cache: re-running it is free when nothing changed, and reliable when
# something did. Letting Make second-guess (via file-mtime rules against
# the build/bin/ directory) made `make build` silently skip rebuilds
# whenever build/bin/bktunnel already existed.

# Build metadata stamped into the binary via `-ldflags "-X main.<name>=..."`
# and surfaced by `bktunnel --version`. Evaluated once per make invocation
# (:= not =) so all targets in a single `make` see the same values —
# otherwise `make build arm64 armv7 armv6` would stamp four slightly
# different times.
#
# Git info is injected manually here (rather than relying on `go build`'s
# default -buildvcs=true) because Go 1.22's cmd/go VCS detector requires
# `.git` to be a directory and returns "no VCS" for git worktrees, where
# `.git` is a file pointing at the actual gitdir. `git` commands work
# fine from a worktree; injecting via ldflags sidesteps Go's stricter
# check. Empty-value fallbacks mean the build still succeeds outside a
# git tree — the corresponding `bktunnel --version` lines are just omitted.
GIT_REV    := $(shell git rev-parse --short HEAD 2>/dev/null)
GIT_TIME   := $(shell git log -1 --format=%cI 2>/dev/null)
GIT_DIRTY  := $(shell git diff-index --quiet HEAD -- 2>/dev/null || echo dirty)
# When the tree is clean, use the commit's timestamp as BuildTime so
# `make build` on a given commit produces byte-identical binaries
# regardless of when it's run — deterministic per commit. When dirty,
# use the actual wall-clock build time (there's no meaningful commit
# time for uncommitted changes).
ifeq ($(GIT_DIRTY),)
BUILD_TIME := $(GIT_TIME)
else
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
endif
# `-trimpath` strips absolute source paths from the compiled binary,
# replacing them with `$GOPATH/src/...`-style relative paths. Result:
# two developers building the same commit from different local checkout
# paths produce byte-identical binaries. Small trade-off: local stack
# traces show the trimmed path instead of the real file path.
BUILD_FLAGS := -trimpath
# LDFLAGS is ?= + exported so `make docker-build`/`docker-deb` can inject the
# HOST-computed value into the container (git resolves on the host, worktree or
# clone); a normal build just derives it here.
LDFLAGS     ?= -ldflags "\
	-X main.BuildTime=$(BUILD_TIME) \
	-X main.GitRev=$(GIT_REV) \
	-X main.GitTime=$(GIT_TIME) \
	-X main.GitDirty=$(GIT_DIRTY)"
export LDFLAGS

# Force a pure-Go static binary (no cgo net/user resolvers) so native
# `make build`/`deb` and `make docker-build`/`docker-deb` produce identical
# bytes regardless of whether a C compiler is present. Override with CGO_ENABLED=1.
CGO_ENABLED ?= 0
export CGO_ENABLED

.PHONY: build
build: | $(BUILD_DIR) ## Build native binary into build/bin/bktunnel (whatever arch the host is).
	$(GO) go build $(BUILD_FLAGS) $(LDFLAGS) -o $(NATIVE) $(PKG)

.PHONY: amd64
amd64: | $(BUILD_DIR) ## Cross-compile linux/amd64 into build/bin/amd64/bktunnel (Intel/AMD x86-64 desktops, laptops, servers, VMs, WSL).
	@mkdir -p $(dir $(AMD64))
	$(GO) GOOS=linux GOARCH=amd64 go build $(BUILD_FLAGS) $(LDFLAGS) -o $(AMD64) $(PKG)

.PHONY: arm64
arm64: | $(BUILD_DIR) ## Cross-compile linux/arm64 into build/bin/arm64/bktunnel (Pi 3/4/5 64-bit, Snapdragon X1 Elite, most modern ARM Linux).
	@mkdir -p $(dir $(ARM64))
	$(GO) GOOS=linux GOARCH=arm64 go build $(BUILD_FLAGS) $(LDFLAGS) -o $(ARM64) $(PKG)

.PHONY: armv7
armv7: | $(BUILD_DIR) ## Cross-compile linux/armv7 into build/bin/armv7/bktunnel (Pi 2 or Pi 3 with 32-bit OS).
	@mkdir -p $(dir $(ARMV7))
	$(GO) GOOS=linux GOARCH=arm GOARM=7 go build $(BUILD_FLAGS) $(LDFLAGS) -o $(ARMV7) $(PKG)

.PHONY: armv6
armv6: | $(BUILD_DIR) ## Cross-compile linux/armv6 into build/bin/armv6/bktunnel (Pi 1, Pi Zero).
	@mkdir -p $(dir $(ARMV6))
	$(GO) GOOS=linux GOARCH=arm GOARM=6 go build $(BUILD_FLAGS) $(LDFLAGS) -o $(ARMV6) $(PKG)

.PHONY: darwin-amd64
darwin-amd64: | $(BUILD_DIR) ## Cross-compile darwin/amd64 into build/bin/darwin-amd64/bktunnel (Intel Macs).
	@mkdir -p $(dir $(DARWIN_AMD64))
	$(GO) GOOS=darwin GOARCH=amd64 go build $(BUILD_FLAGS) $(LDFLAGS) -o $(DARWIN_AMD64) $(PKG)

.PHONY: darwin-arm64
darwin-arm64: | $(BUILD_DIR) ## Cross-compile darwin/arm64 into build/bin/darwin-arm64/bktunnel (Apple Silicon Macs — M1/M2/M3/M4).
	@mkdir -p $(dir $(DARWIN_ARM64))
	$(GO) GOOS=darwin GOARCH=arm64 go build $(BUILD_FLAGS) $(LDFLAGS) -o $(DARWIN_ARM64) $(PKG)

.PHONY: build-all
build-all: amd64 arm64 armv7 armv6 darwin-amd64 darwin-arm64 ## Build every cross-compile target into build/bin/.

# DOCKER_BUILD_HELPER runs a make target inside a golang container, so the
# binaries (and .deb packages) can be built on a host with no Go — or even no
# dpkg — installed. The repo is bind-mounted, the build runs as your own user
# (outputs stay yours, not root's), and Go's build cache is mounted from the
# host when present or created under /tmp otherwise. The version-stamp vars are
# computed on the HOST (git resolves there, worktree or clone) and injected via
# -e, so no git is needed inside the container.
DOCKER_BUILD_HELPER = docker run \
	--rm \
	--user $(shell id -u):$(shell id -g) \
	-v $(shell pwd):/tmp/build/src \
	-v $(shell bash -c 'go env GOCACHE 2>/dev/null || (mkdir -p /tmp/bktunnel-go-cache; echo /tmp/bktunnel-go-cache)'):/tmp/build/.cache \
	-e LDFLAGS -e DEB_VERSION -e SOURCE_DATE_EPOCH \
	bktunnel-builder

# Build the builder image (cheap to re-run: Docker layer-caches it). Both
# docker-build and docker-deb depend on it.
.PHONY: docker-builder-image
docker-builder-image:
	docker build -t bktunnel-builder -f make/builder.Dockerfile make/

.PHONY: docker-build
docker-build: docker-builder-image ## Cross-compile all targets inside Docker (no host Go needed); outputs to build/bin/.
	$(DOCKER_BUILD_HELPER) make build-all

.PHONY: test
test: ## Run all tests, verbose (interop tests fail unless stunnel, xxd, openssl are installed).
	$(GO) go test -v ./...

.PHONY: test-interop
test-interop: ## Run only the interop tests, verbose (fails unless stunnel, xxd, openssl are installed).
	$(GO) go test -run Interop -v ./...

.PHONY: test-go
test-go: ## Run only the Go-only end-to-end tests, verbose (needs nothing but the Go toolchain).
	$(GO) go test -run '^TestGo' -v ./...

.PHONY: test-conformance
test-conformance: ## Run the Python wire-conformance interop tests (needs python3 + cryptography; stunnel/xxd/openssl for the bash pairings).
	$(GO) go test -tags conformance -run Conformance -v ./...

.PHONY: clean
clean: ## Remove built binaries.
	rm -rf $(BUILD_DIR)

##@ Install (local)

.PHONY: install-user
install-user: build ## Install bktunnel into a per-user location (no sudo).
	@mkdir -p "$(USER_BIN)"
	@install -m 0755 $(NATIVE) "$(USER_BIN)/bktunnel"
	@echo "Installed bktunnel to $(USER_BIN)/bktunnel"
	@case ":$$PATH:" in *":$(USER_BIN):"*) ;; *) echo "Note: $(USER_BIN) is not in your PATH." ;; esac

.PHONY: install-system
install-system: build ## Install bktunnel into a system location (requires sudo).
	@sudo install -m 0755 $(NATIVE) "$(SYSTEM_BIN)/bktunnel"
	@echo "Installed bktunnel to $(SYSTEM_BIN)/bktunnel"

.PHONY: uninstall-user
uninstall-user: ## Remove bktunnel from the per-user location.
	@rm -f "$(USER_BIN)/bktunnel"
	@echo "Removed $(USER_BIN)/bktunnel"

.PHONY: uninstall-system
uninstall-system: ## Remove bktunnel from the system location (requires sudo).
	@sudo rm -f "$(SYSTEM_BIN)/bktunnel"
	@echo "Removed $(SYSTEM_BIN)/bktunnel"

##@ Package

# Debian .deb package. Uses `dpkg-deb --build` (part of dpkg on
# Debian/Ubuntu) rather than debhelper to keep the recipe
# self-contained. Layout follows Debian's FHS conventions:
#   /usr/bin/bktunnel
#   /usr/lib/systemd/system/bktunnel@.service   (systemd template unit)
#   /usr/share/doc/bktunnel/examples/           (config samples)
# plus DEBIAN/postinst + postrm that run `systemctl daemon-reload`.
#
# Requires `dpkg-deb` in PATH. Version is derived from
# `git describe --tags --always --dirty`, with the leading `v`
# stripped and hyphens replaced by `.` so the result is a valid
# Debian upstream_version (no implicit debian_revision separator).
# Falls back to `0.0.0` outside a git tree; when no tag is present
# the sha is prefixed with `0.0.0.` so the version still starts
# with a digit as Debian requires.
#
# Cross-arch .debs (deb-arm64 / deb-armv7 / deb-armv6) reuse the
# corresponding Go cross-build targets. Go arch → Debian arch:
#   amd64          →  amd64
#   arm64          →  arm64
#   arm GOARM=7    →  armhf
#   arm GOARM=6    →  armel

DEB_NAME       := bktunnel
# ?= + export so `make docker-deb` injects the HOST-computed version (git
# resolves on the host; the container has no git access in a worktree).
DEB_VERSION    ?= $(shell (git describe --tags --always --dirty 2>/dev/null || echo 0.0.0) | sed -e 's/^v//' -e 's/-/./g' -e 's/^[^0-9].*/0.0.0.&/')
export DEB_VERSION
DEB_MAINTAINER ?= bktunnel maintainers <noreply@example.invalid>
DEB_DESC       := pinned-identity, mutual-auth TLS tunnel

DEB_STAGE := $(PKG_DIR)/deb-stage

# Determinism for .deb output. Set SOURCE_DATE_EPOCH so both
# dpkg-deb's archive-header timestamp AND the mtimes we set on
# staged files use a fixed value derived from the commit — same
# principle as BUILD_TIME above. Clean tree uses the commit's
# unix timestamp; dirty tree uses wall-clock (no meaningful commit
# time for uncommitted work). dpkg-deb 1.19+ honors this env var.
ifeq ($(GIT_DIRTY),)
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || date +%s)
else
SOURCE_DATE_EPOCH ?= $(shell date +%s)
endif
export SOURCE_DATE_EPOCH

# Map the current host's Go arch (from `go env`) to the equivalent
# Debian arch, so `make deb` produces a correctly-labelled .deb for
# whichever machine is running make. Only the common architectures
# are mapped explicitly; anything else falls back to GOARCH as-is
# and may or may not be a valid Debian arch string.
HOST_GOARCH := $(shell go env GOARCH)
HOST_GOARM  := $(shell go env GOARM)
ifeq ($(HOST_GOARCH),amd64)
  HOST_DEB_ARCH := amd64
else ifeq ($(HOST_GOARCH),arm64)
  HOST_DEB_ARCH := arm64
else ifeq ($(HOST_GOARCH),386)
  HOST_DEB_ARCH := i386
else ifeq ($(HOST_GOARCH),arm)
  ifeq ($(HOST_GOARM),6)
    HOST_DEB_ARCH := armel
  else
    HOST_DEB_ARCH := armhf
  endif
else
  HOST_DEB_ARCH := $(HOST_GOARCH)
endif

# do_deb: build a .deb from a pre-built binary. $(1) is the local
# binary path (build/bin/bktunnel, build/bin/arm64/bktunnel, etc.); $(2) is
# the Debian architecture string (amd64, arm64, armhf, armel).
define do_deb
	@rm -rf "$(DEB_STAGE)"
	@mkdir -p "$(PKG_DIR)" "$(DEB_STAGE)/DEBIAN" "$(DEB_STAGE)/usr/bin" \
	          "$(DEB_STAGE)/usr/lib/systemd/system" \
	          "$(DEB_STAGE)/usr/share/doc/bktunnel/examples"
	@install -m 0755 $(1) "$(DEB_STAGE)/usr/bin/bktunnel"
	@install -m 0644 packaging/systemd/bktunnel@.service "$(DEB_STAGE)/usr/lib/systemd/system/bktunnel@.service"
	@install -m 0644 packaging/systemd/bktunnel.conf.example packaging/systemd/bktunnel.peers.example \
		"$(DEB_STAGE)/usr/share/doc/bktunnel/examples/"
	@size=$$(du -k --apparent-size -s "$(DEB_STAGE)/usr" | cut -f1); \
	printf 'Package: %s\nVersion: %s\nSection: net\nPriority: optional\nArchitecture: %s\nMaintainer: %s\nInstalled-Size: %s\nDescription: %s\n' \
		"$(DEB_NAME)" "$(DEB_VERSION)" "$(2)" "$(DEB_MAINTAINER)" "$$size" "$(DEB_DESC)" \
		> "$(DEB_STAGE)/DEBIAN/control"
	@cd "$(DEB_STAGE)" && find usr -type f -exec md5sum {} + > DEBIAN/md5sums
	@printf '#!/bin/sh\nset -e\nif [ -d /run/systemd/system ]; then systemctl daemon-reload || true; fi\n' \
		> "$(DEB_STAGE)/DEBIAN/postinst"
	@cp "$(DEB_STAGE)/DEBIAN/postinst" "$(DEB_STAGE)/DEBIAN/postrm"
	@chmod 0755 "$(DEB_STAGE)/DEBIAN/postinst" "$(DEB_STAGE)/DEBIAN/postrm"
	@find "$(DEB_STAGE)" -exec touch -h -d "@$(SOURCE_DATE_EPOCH)" {} +
	@dpkg-deb --build --root-owner-group "$(DEB_STAGE)" "$(PKG_DIR)/$(DEB_NAME)_$(DEB_VERSION)_$(2).deb" >/dev/null
	@rm -rf "$(DEB_STAGE)"
	@echo "Built $(PKG_DIR)/$(DEB_NAME)_$(DEB_VERSION)_$(2).deb"
endef

.PHONY: deb
deb: build ## Build a Debian .deb package for the current host arch into build/packages/.
	$(call do_deb,$(NATIVE),$(HOST_DEB_ARCH))

.PHONY: deb-amd64
deb-amd64: amd64 ## Build a Debian .deb package (amd64) into build/packages/ (Intel/AMD x86-64 desktops, laptops, servers, VMs, WSL).
	$(call do_deb,$(AMD64),amd64)

.PHONY: deb-arm64
deb-arm64: arm64 ## Build a Debian .deb package (arm64) into build/packages/ (Pi 3/4/5 64-bit, Snapdragon X1 Elite, most modern ARM Linux).
	$(call do_deb,$(ARM64),arm64)

.PHONY: deb-armv7
deb-armv7: armv7 ## Build a Debian .deb package (armhf) into build/packages/ (Pi 2 or Pi 3 with 32-bit OS).
	$(call do_deb,$(ARMV7),armhf)

.PHONY: deb-armv6
deb-armv6: armv6 ## Build a Debian .deb package (armel) into build/packages/ (Pi 1, Pi Zero).
	$(call do_deb,$(ARMV6),armel)

.PHONY: deb-all
deb-all: deb-amd64 deb-arm64 deb-armv7 deb-armv6 ## Build every Debian .deb package variant into build/packages/.

.PHONY: docker-deb
docker-deb: docker-builder-image ## Build every .deb inside Docker (no host Go/dpkg needed); outputs to build/packages/.
	$(DOCKER_BUILD_HELPER) make deb-all

