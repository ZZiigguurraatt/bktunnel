# Builder image for `make docker-build`: compiles the bktunnel Go binaries on a
# host that has no Go toolchain installed. Nothing is copied in — the repo is
# bind-mounted at run time (see the docker-build target in ../Makefile).
#
# Pinned by digest for reproducible, tamper-evident builds: Docker resolves the
# image by the @sha256 digest, so the tag is only a human hint. This is the
# multi-arch index digest, so it still selects the right variant on any host.
# The version should track go/go.mod's toolchain line. To bump Go, pick a new
# golang:<ver>-bookworm and refresh the digest with:
#   docker buildx imagetools inspect golang:<ver>-bookworm --format '{{.Manifest.Digest}}'
FROM golang:1.22.2-bookworm@sha256:d0902bacefdde1cf45528c098d14e55d78c107def8a22d148eabd71582d7a99f

# Self-contained, reproducible builds: no cgo, and never fetch a toolchain other
# than the one baked into this image.
ENV CGO_ENABLED=0
ENV GOTOOLCHAIN=local

# GOCACHE is bind-mounted from the host to speed repeat builds; GOMODCACHE is
# unused (the tool has no dependencies) but points at a writable path so a
# non-root --user can still build.
ENV GOCACHE=/tmp/build/.cache
ENV GOMODCACHE=/tmp/build/.modcache

RUN apt-get update \
    && apt-get install -y --no-install-recommends make git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /tmp/build/src /tmp/build/.cache /tmp/build/.modcache \
    && chmod -R 777 /tmp/build

WORKDIR /tmp/build/src
