# barekey-tunnel

Builds a mutually-authenticated TLS tunnel between two hosts using **pinned
public keys** (Ed25519 by default, or ECDSA P-256).

Trust is by pinned public keys, not by a CA. Each side holds a stable private
key — Ed25519 by default, or ECDSA P-256 for a peer that must be a browser or
mobile client — and pins the *other* side's public key. No certificate
authority, no expiry checks; ephemeral certs and key files derived at runtime
stay off persistent storage.

There are two interchangeable implementations that share one CLI and key
format — a single-file `bash` wrapper around
[`stunnel`](https://www.stunnel.org/), and a dependency-free `go/` binary. See
[Implementations](#implementations) for how to choose.

> **Note:** only **TCP** sockets are tunneled. UDP is not supported — the
> transport carries a TCP stream.

## What it is

`bktunnel` is a **static, single-destination TLS proxy** (a port forwarder): it
listens on one local socket and relays every connection to one fixed address
chosen at startup with `-c`. It is **not** a SOCKS or HTTP proxy — the client
can't pick the destination, and `bktunnel` never inspects or routes the traffic
it carries.

- **Compact key format.** Each identity is a single 44-character base64 line —
  the raw private key (secret) or public key (shareable). There
  are no multi-line PEM certificates to copy around; you hand over one short
  line, the way you would a WireGuard key or an SSH `authorized_keys` entry.
- **Pinned identity.** Each peer is trusted by its raw public key (Ed25519 or ECDSA P-256). Any
  certificate involved is just a carrier for that key, verified against the
  pinned public key.
- **No certificates to manage.** TLS requires each end to present an X.509
  certificate, but you never create, sign, distribute, or renew one with
  `bktunnel`. From your bare 32-byte key the tool synthesizes a throwaway
  carrier cert at startup, purely to satisfy the TLS layer. Because trust rests
  on the pinned public key rather than any CA, the cert is a formality you never
  touch — dealing in bare keys instead of certs is the point (and the name).

  This is the trust model of [RFC 7250](https://www.rfc-editor.org/rfc/rfc7250)
  (raw public keys, pinned out-of-band, no CA), realized over stock X.509 TLS:
  RFC 7250 puts the bare public key on the wire via a negotiated certificate
  type; `bktunnel`, needing to run on stacks that lack that type, instead has
  **each end** wrap its own raw key in a throwaway carrier cert at startup
  and present that. The cert is purely a workaround for TLS stacks that don't
  speak RFC 7250 — it's the same key either way, just enveloped so any X.509
  stack will parse it and hand it to the pin check. RFC 7250 support today is library-level — GnuTLS,
  wolfSSL, OpenSSL 3.2+, rustls — and deployed mostly in constrained IoT
  (CoAP-over-DTLS), not in general-purpose tunnels. Most other popular stacks
  still lack it — Go's `crypto/tls`, BoringSSL, NSS, Java's JSSE, Windows
  Schannel, LibreSSL, mbedTLS — and stunnel doesn't expose OpenSSL's support.
  Wrapping OpenSSL isn't enough on its own, either: runtimes built on it, such
  as Python's `ssl` and Node's `tls`, don't surface the raw-public-key APIs even
  when linked against OpenSSL 3.2+. That is why the carrier-cert approach is the
  portable one.
- **Mutual auth.** Both ends verify the other against the pinned public key.
- **Private keys and ephemeral certs stay in RAM.** stunnel and openssl only read keys and certs
  from files, so the bash implementation must write your private key to a file
  in a temporary RAM filesystem (tmpfs) and, from that file, create a temporary
  carrier cert. Both files live only in tmpfs and are removed with
  [`shred`](https://www.gnu.org/software/coreutils/manual/html_node/shred-invocation.html)
  on exit, never touching persistent storage. The Go implementation needs no files — it
  holds the private key and ephemeral generated cert in process memory. Where
  your private key lives *at
  rest* is a separate matter: generate it to a file with `-g FILE`, or supply
  it at run time via `-k @FILE`, `-k -`, or `TUNNEL_PRIVKEY` — you decide
  whether it lives on disk.

## Why use it

`bktunnel` secures a single TCP socket end-to-end without the operational
weight of standing up a full VPN. Compared with running a WireGuard tunnel just
to protect one service, you avoid:

- **A tunnel interface to manage.** No `wg0` device to create, bring up, and
  keep alive — it's just a process that exits cleanly and takes its keys with
  it.
- **Tunnel IP addressing.** No private subnet to allocate, assign to the
  interface, and route; the tunnel is a plain `accept` → `connect` socket
  forward, so it drops into existing addressing unchanged.
- **An externally exposed UDP port.** WireGuard needs an inbound UDP port open
  on the firewall for tunnel traffic. `bktunnel` rides a single TLS/TCP
  connection to the port your service already uses — nothing extra to expose.
- **Securing the internal network.** Because encryption is per-socket and
  mutually authenticated at the endpoints, you don't have to treat the tunnel
  subnet as trusted or firewall lateral movement across it — only the two
  pinned peers can talk, and only over that one forwarded socket.

## Architecture

The arrows show the order in which connections are opened, top to bottom: your
application connects in plaintext to the local `bktunnel` client, which dials
the `bktunnel` server over pinned, mutually-authenticated TLS, which in turn
connects in plaintext to the real service. Once the path is up, data flows both
ways across it.

```
  +--------------------------------------------------+
  | your application                                 |
  +--------------------------------------------------+
         |
         v   plaintext TCP (local)
  +--------------------------------------------------+
  | CLIENT host   (bktunnel -r client)               |
  |                                                  |
  | holds : CLIENT privkey   secret, never shared    |
  | pins  : SERVER pubkey    from server, via -p     |
  |                                                  |
  | -a 127.0.0.1:5560        listen  (plaintext in)  |
  | -c server.example:5560   dial    (TLS out)       |
  +--------------------------------------------------+
         |
         v
      .-~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~-.
    .-(                                          )-.
    (  UNTRUSTED NETWORK                         )
    (                                            )
    (  only ciphertext crosses here:             )
    (  mutually-authenticated TLS with           )
    (  pinned public keys, so a MITM             )
    (  can neither read the stream nor           )
    (  impersonate either peer                   )
    '-(                                          )-'
      `-~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~-'
         |
         v
  +--------------------------------------------------+
  | SERVER host   (bktunnel -r server)               |
  |                                                  |
  | holds : SERVER privkey   secret, never shared    |
  | pins  : CLIENT pubkey    from client, via -p     |
  |                                                  |
  | -a 0.0.0.0:5560          listen  (TLS in)        |
  | -c 127.0.0.1:1883        dial    (plaintext out) |
  +--------------------------------------------------+
         |
         v   plaintext TCP (local)
  +--------------------------------------------------+
  | local service   127.0.0.1:1883   (e.g. MQTT)     |
  +--------------------------------------------------+
```

Each host generates its own keypair once with `bktunnel -g`. The private keys
never move; only the public keys are exchanged out-of-band, and each host pins
the *other's*:

```
  CLIENT privkey   stays on the client   (feeds the client's own -k)
  SERVER privkey   stays on the server   (feeds the server's own -k)

  CLIENT pubkey  ---->  handed to the SERVER, pinned there with -p
  SERVER pubkey  ---->  handed to the CLIENT, pinned there with -p
```

## Roles: `-a` (accept) vs `-c` (connect)

| Role     | `-a` accept (listen)        | `-c` connect (forward to)      |
|----------|-----------------------------|--------------------------------|
| `client` | local plaintext in          | TLS out to the **remote peer** |
| `server` | TLS in from the peer        | **local** plaintext service    |

## Connection behavior

Both roles are **long-running listeners**: whichever end you run keeps listening
for the life of the process, and a peer connecting then disconnecting does not
stop it. Each accepted connection is handled independently and mapped one-to-one
to a downstream connection — the server's `-c` backend dial, or the client's TLS
dial to the server — opened on connect and torn down on disconnect (nothing is
pooled or reused). Connections are served concurrently, so one peer
disconnecting leaves the others untouched. The process exits only on a fatal
listener error or when killed, never on a peer disconnect.

Each end bridges two TCP connections — on the client, the local plaintext one
and the TLS one to the server — and relays both the bytes **and the connection
close** between them, in each direction. A graceful close on one side passes
through as a close on the other, and TCP half-closes are preserved (one
direction's EOF is signalled to the peer while the reverse keeps flowing). An
abrupt break, such as the TLS socket dropping, instead closes both sides at
once. In all cases `bktunnel` relays the connection's lifecycle rather than
forwarding raw TCP segments.

`bktunnel` does not reconnect or buffer. When a connection breaks — a network
blip, or the server going away — the teardown surfaces to the application as an
ordinary TCP close, and there is no retry, backoff, or session resumption; if
the server is unreachable when a connection is made, the local connection is
closed at once. Recovery is the application's job: because the listener stays
up, the app just opens a new connection, which triggers a fresh TLS dial.
Applications that already retry a dropped socket (most DB drivers, MQTT clients,
and the like) get transparent recovery for free.

## Relation to other tools

### WireGuard

The key-exchange workflow will feel familiar if you've used
[WireGuard](https://www.wireguard.com/): each host holds a static private key,
you exchange the corresponding public keys out-of-band (base64), and
each side pins the other's public key. There is no CA and no PKI — trust is
purely by pinned key, exactly like WireGuard peers.

The differences are in what happens underneath:

- **Transport.** WireGuard is a layer-3 VPN over UDP using the Noise protocol.
  `bktunnel` wraps an arbitrary **TCP** stream in ordinary **TLS** — the
  public keys are carried inside certificates and verified against the pin.
- **Key type.** WireGuard uses Curve25519 (X25519) keys for its handshake.
  `bktunnel` uses **Ed25519** (or ECDSA P-256) signing identities; the actual session keys
  come from the TLS handshake, not from the pinned keys directly.
- **Scope.** WireGuard forwards IP packets and can route whole networks.
  `bktunnel` forwards a single point-to-point socket (one `accept` → one
  `connect`), like an SSH `-L`/`-R` forward.

### SSH tunnels

Functionally the forward resembles an SSH tunnel (`ssh -L`/`-R`): a local port
is encrypted, carried to the other host, and delivered to a destination there.

The important difference is **scope of access**. An SSH tunnel is layered on top of
an authenticated login to the remote system — establishing it means granting an
account, and that same channel can (subject to config) open a shell, run
commands, read files, or set up further forwards. `bktunnel` grants **none
of that**: there is no remote account, no shell, and no login. A peer can reach
**exactly one destination** — the single `connect` address the server was
started with — and nothing else on the host or its network. The pinned keys
authenticate the *tunnel endpoints*, not a user session, so a compromised or
misbehaving peer cannot pivot beyond that one forwarded socket.

## Implementations

Both implementations expose the same flags (`-r/-a/-c/-k/-p/-g`), the same
`privkey`/`pubkey` base64 key format, and the same `TUNNEL_PRIVKEY` environment
variable, so a keypair or command line works with either. They are also
**wire-compatible**: a bash node and a Go node interoperate on the same tunnel
(the Go side presents an Ed25519 or P-256 carrier cert whose CN uses the same
`sha256(SPKI)[:40]` scheme the bash side pins on). This is exercised by the
interop tests — see [Tests](#tests).

| | `bktunnel` (bash) | `go/` (binary) |
|---|---|---|
| Transport | `stunnel` (TLS) | Go `crypto/tls` (TLS 1.2+) |
| Dependencies | `stunnel`, `openssl`, `xxd`, coreutils | none (single self-contained binary) |
| Key handling | identity cert + pin cert per peer, via `openssl` | raw-pubkey pin in `VerifyPeerCertificate` |
| RAM-only keys | files in `/dev/shm`, `shred`-ed on exit | never leave process memory; nothing written |
| Deploy | copy the script to any box with the deps | build/cross-compile one binary |

- **Reach for the bash version** when you want a zero-build script you can drop
  onto any host that already has `stunnel`, and you'd rather delegate the
  TLS termination to a mature, separately-audited program.
- **Reach for the Go version** when you want a single self-contained binary with
  no runtime dependencies and keys that never touch the filesystem at all.

> **Pick one per host — the bash script *or* the Go binary, not both.** They are
> both named `bktunnel` and install to the same path, so installing one
> overwrites the other; a single host runs one or the other. This is only a
> *per-host* choice, never a per-tunnel one: because the two are
> wire-compatible, the two ends of a tunnel need **not** match — a bash host and
> a Go host interoperate fine as the two ends.

The command-line documentation below uses the `bktunnel` script in its examples;
the Go binary takes the same flags and behaves identically. See
[Go implementation](#go-implementation) to build it.

## bash implementation

### Requirements

- `bash`, `openssl` (with Ed25519 support), `stunnel`
- `xxd`, `base64`, `shred`, `mktemp`, `sha256sum` (coreutils / vim-common)
- A RAM-backed `/dev/shm` (default `CFG_RUNDIR_BASE`)

### Install

On Ubuntu/Debian, install `stunnel` (and the `xxd` helper, part of
`vim-common`) from the package repos:

```sh
sudo apt update
sudo apt install stunnel4 vim-common
```

`openssl`, `base64`, `shred`, and `mktemp` (coreutils) are already present on a
standard Ubuntu install. Then drop the script onto your `PATH`:

```sh
install -m 0755 bktunnel /usr/local/bin/bktunnel
```

## Go implementation

The Go implementation lives in `go/` — a module
(`github.com/zziigguurraatt/bktunnel/go`) with the command under
`go/cmd/bktunnel`, kept in its own subdirectory so the built `bktunnel` binary
can't collide with the bash script of the same name at the repo root.

### Build dependencies (Ubuntu)

The project is pure Go — no cgo, no system C libraries — so cross-compiling
to ARM (Raspberry Pi), Apple Silicon, etc. works out of the box without
needing a cross-gcc toolchain. You just need Go ≥ 1.22 and `make`.

`go/go.mod` pins a specific Go patch version via the `toolchain` directive
(currently `go1.22.2`). If your installed `go` is older than that but at
least 1.22, Go will auto-fetch the pinned toolchain via `proxy.golang.org`
the first time you build. Newer local Go installs are used as-is.

On **Ubuntu 24.04 or newer**, the apt-packaged Go is recent enough:

```
sudo apt install golang-go make
```

On **older Ubuntu releases** the apt-packaged Go is too old. Grab the
latest Go tarball from <https://go.dev/dl/> and put it in your PATH:

```
sudo apt install make
# Then follow https://go.dev/doc/install
```

### Quick install (no clone)

Once Go is installed you can fetch and build directly with `go install`:

```
go install github.com/zziigguurraatt/bktunnel/go/cmd/bktunnel@latest
```

This drops the `bktunnel` binary in `$(go env GOBIN)` (which falls back to
`$GOPATH/bin`, usually `~/go/bin/`). Make sure that's in your `PATH`.

`go install` only produces a native binary; if you want a cross-compiled
build (e.g. for a Raspberry Pi), clone the repo and use the Makefile
targets below.

### Nix flake

If you have [Nix](https://nixos.org/) with flakes enabled, you can run
`bktunnel` without installing anything into your profile:

```
nix run github:zziigguurraatt/bktunnel#bktunnel -- -g -
```

Or, from a clone:

```
nix run .#bktunnel -- -k @/etc/tunnel/privkey -P
```

Everything after `--` is forwarded to `bktunnel` verbatim
(`nix run .#bktunnel -- --version`, `nix run .#bktunnel -- -h`).

To build the package (binary lands in `result/bin/bktunnel`):

```
nix build .#bktunnel
```

Or install it into your profile:

```
nix profile install github:zziigguurraatt/bktunnel#bktunnel
```

The flake builds the `go/` module with `buildGoModule`. Since the tool
has no dependencies, `vendorHash` is `null` (nothing to vendor) — there
is no hash to bump when you touch `go/go.mod`.

Like `go install`, the flake produces only a native binary (for the host
system); for a cross-compiled Raspberry Pi build use the Makefile targets
below.

### Builds (from a clone)

A `Makefile` is provided. Run `make help` to list every target with a
short description:

```
$ make help

Usage:
  make <target>

General
  help                Display this help.

Build
  build               Build native binary into build/bin/bktunnel (whatever arch the host is).
  amd64               Cross-compile linux/amd64 into build/bin/amd64/bktunnel (Intel/AMD x86-64 desktops, laptops, servers, VMs, WSL).
  arm64               Cross-compile linux/arm64 into build/bin/arm64/bktunnel (Pi 3/4/5 64-bit, Snapdragon X1 Elite, most modern ARM Linux).
  armv7               Cross-compile linux/armv7 into build/bin/armv7/bktunnel (Pi 2 or Pi 3 with 32-bit OS).
  armv6               Cross-compile linux/armv6 into build/bin/armv6/bktunnel (Pi 1, Pi Zero).
  darwin-amd64        Cross-compile darwin/amd64 into build/bin/darwin-amd64/bktunnel (Intel Macs).
  darwin-arm64        Cross-compile darwin/arm64 into build/bin/darwin-arm64/bktunnel (Apple Silicon Macs — M1/M2/M3/M4).
  build-all           Build every cross-compile target into build/bin/.
  docker-build        Cross-compile all targets inside Docker (no host Go needed); outputs to build/bin/.
  test                Run all tests, verbose (interop tests fail unless stunnel, xxd, openssl are installed).
  test-interop        Run only the interop tests, verbose (fails unless stunnel, xxd, openssl are installed).
  test-go             Run only the Go-only end-to-end tests, verbose (needs nothing but the Go toolchain).
  test-conformance    Run the Python wire-conformance interop tests (needs python3 + cryptography; stunnel/xxd/openssl for the bash pairings).
  clean               Remove built binaries.

Install (local)
  install-user        Install bktunnel into a per-user location (no sudo).
  install-system      Install bktunnel into a system location (requires sudo).
  uninstall-user      Remove bktunnel from the per-user location.
  uninstall-system    Remove bktunnel from the system location (requires sudo).

Package
  deb                 Build a Debian .deb package for the current host arch into build/packages/.
  deb-amd64           Build a Debian .deb package (amd64) into build/packages/ (Intel/AMD x86-64 desktops, laptops, servers, VMs, WSL).
  deb-arm64           Build a Debian .deb package (arm64) into build/packages/ (Pi 3/4/5 64-bit, Snapdragon X1 Elite, most modern ARM Linux).
  deb-armv7           Build a Debian .deb package (armhf) into build/packages/ (Pi 2 or Pi 3 with 32-bit OS).
  deb-armv6           Build a Debian .deb package (armel) into build/packages/ (Pi 1, Pi Zero).
  deb-all             Build every Debian .deb package variant into build/packages/.
  docker-deb          Build every .deb inside Docker (no host Go/dpkg needed); outputs to build/packages/.
```

Native build:

```
make            # builds build/bin/bktunnel
```

Install locally — pick one:

```
make install-user      # → $GOBIN/bktunnel (same place `go install` uses; no sudo)
make install-system    # → /usr/local/bin/bktunnel                 (requires sudo)
```

If `GOBIN` isn't set, `make install-user` falls back to `$(go env GOPATH)/bin`,
which is typically `~/go/bin/`. Override with `make install-user
USER_BIN=$HOME/.local/bin` (or any other path).

### Building in Docker (no Go on the host)

If the machine has no Go toolchain (or no `dpkg`), the `docker-*` targets run
the build in a `golang` container instead — an *alternative* to the native
targets above, not a replacement (`make build`, `make deb`, etc. still work
whenever the host has the tools). `make docker-build` cross-compiles the
binaries; `make docker-deb` builds the `.deb` packages. Each builds a small
builder image (`make/builder.Dockerfile`), then runs the matching native target
(`build-all` / `deb-all`) in it with the repo bind-mounted, so outputs land in
`build/bin/` and `build/packages/` on the host exactly as a native build would:

```sh
make docker-build   # binaries      -> build/bin/<arch>/bktunnel
make docker-deb     # .deb packages -> build/packages/
```

The compile runs as your own user, so the outputs are owned by you rather than
root, and Go's build cache is reused from the host when present. The builder's
base image is pinned by SHA-256 digest in `make/builder.Dockerfile` (a
`golang:1.22.2-bookworm` matching `go/go.mod`) for reproducible, tamper-evident
builds, and `GOTOOLCHAIN=local` stops the build from fetching any other
toolchain, so it works offline.

### Debian package

`make deb` builds a `.deb` archive suitable for installation with
`dpkg -i` (or via `apt install ./bktunnel_*.deb`) on Debian/Ubuntu-family
distros:

```
make deb
sudo dpkg -i build/packages/bktunnel_0.0.0.<sha>_amd64.deb
```

The package installs `bktunnel` to `/usr/bin/`, the systemd template unit to
`/usr/lib/systemd/system/bktunnel@.service`, and the config samples to
`/usr/share/doc/bktunnel/examples/`; a `postinst`/`postrm` runs
`systemctl daemon-reload`. (The template isn't auto-enabled — create
`/etc/bktunnel/<name>.{conf,key,peers}` and `systemctl enable --now bktunnel@<name>`;
see [Running as a service](#running-as-a-service).) The package version is derived
from `git describe --tags --always --dirty`; without a tag it falls
back to `0.0.0.<sha>` so uploads remain valid Debian version strings.
Override the maintainer field with `make deb DEB_MAINTAINER="Your
Name <you@example.com>"`.

Requires the `dpkg-deb` tool (dpkg **≥ 1.19.0**, i.e. Debian ≥ 10 /
Ubuntu ≥ 18.04 — earlier releases lack the `--root-owner-group` flag)
in `PATH`. Every Debian/Ubuntu host has this preinstalled. On
non-Debian hosts (Fedora, Arch, macOS, …) install `dpkg` via your
package manager first: `dnf install dpkg`, `pacman -S dpkg`,
`brew install dpkg`.

`make deb` detects the host's arch via `go env GOARCH`/`GOARM` and
labels the .deb accordingly — so building on an amd64 host produces
an amd64 .deb, building on an arm64 host produces an arm64 .deb,
etc. For explicit control (or to cross-compile), use one of the
arch-specific targets:

| Make target   | Go arch     | Debian arch | Target device                                                      |
|---------------|-------------|-------------|--------------------------------------------------------------------|
| `deb-amd64`   | amd64       | amd64       | 64-bit x86 Linux                                                   |
| `deb-arm64`   | arm64       | arm64       | Raspberry Pi 3/4/5 (64-bit OS), Snapdragon X1 Elite, most ARM64    |
| `deb-armv7`   | arm GOARM=7 | armhf       | Raspberry Pi 2 / Pi 3 (32-bit OS)                                  |
| `deb-armv6`   | arm GOARM=6 | armel       | Raspberry Pi 1 / Pi Zero                                           |

Running any of these produces `build/packages/bktunnel_<version>_<arch>.deb`;
`make deb-all` builds every variant.

### Reproducible builds

Both `make build*` and `make deb*` produce byte-identical output for
the same source tree, so you can verify a build didn't get tampered
with by rebuilding and comparing sha256s. Four things make this work:

1. **`BuildTime` = commit time when clean.** The `-X main.BuildTime`
   ldflag is set from `git log -1 --format=%cI` when the working
   tree matches `HEAD`. On a dirty tree it falls back to the current
   wall-clock time (so dirty builds are *not* reproducible — you'll
   see `-dirty` in `bktunnel --version` output when this happens).
2. **`-trimpath`.** All `go build` invocations pass `-trimpath`, which
   strips the absolute path of the source tree from the binary. Two
   users building the same commit from `/home/alice/…` vs
   `/home/bob/…` get identical binaries.
3. **Pinned Go toolchain.** `go/go.mod` sets `toolchain go1.22.2`. If
   your local `go` is older than that (but at least 1.22), Go will
   auto-fetch the pinned toolchain via `proxy.golang.org`. Everyone
   building at the same commit uses the same compiler, matching
   codegen exactly.
4. **`SOURCE_DATE_EPOCH` for `.deb` packages.** The Makefile derives
   `SOURCE_DATE_EPOCH` from `git log -1 --format=%ct` (on clean
   trees) and both exports it (`dpkg-deb` consumes it for the
   embedded ar/tar headers) *and* `touch`es every staged file to
   that timestamp before packaging. This eliminates the two
   time-varying inputs that would otherwise churn the archive hash
   from run to run.

Quick check:

```
rm -rf build && make build-all && sha256sum build/bin/*/bktunnel > /tmp/a
rm -rf build && make build-all && sha256sum build/bin/*/bktunnel > /tmp/b
diff /tmp/a /tmp/b     # should be empty

rm -rf build && make deb-all && sha256sum build/packages/*.deb > /tmp/a
rm -rf build && make deb-all && sha256sum build/packages/*.deb > /tmp/b
diff /tmp/a /tmp/b     # should be empty
```


### Versioning

The Go binary embeds its git revision and build time. Print them with `-v`,
`--version`, or the `version` subcommand:

```console
$ bktunnel --version
bktunnel (Go implementation)
go:     go1.22.2
git:    a1b2c3d
built:  2026-07-22T10:50:25-04:00
```

A plain `go install` / `go build` (no ldflags) still works — the git/build
lines are just omitted. (This is a Go-only extra; the bash script has no
`--version`.)

## Quick start

### 1. Generate a keypair on each host

```sh
# print a fresh keypair to stdout
bktunnel -g -
# privkey ed25519 <base64>   <- secret: this host's identity
# pubkey  ed25519 <base64>   <- shareable: hand to the PEER's -p
```

Or run `bktunnel -g` with no argument to save the pair to
`~/.bktunnel/id_ed25519(.pub)`; it prompts for the path (Enter accepts the
default) — see [Default key files](#default-key-files-bktunnel).

Give each host's `pubkey` line to the *other* host. Keep the `privkey` secret —
store it in a file with permissions `0600` (owner-only) or a secrets manager,
never in shell history.

Those two labelled lines are what `-g -` prints **to a terminal**. When it's
**piped or redirected**, `-g -` prints only the bare `privkey` (one line, no
label) for machine use — e.g. `priv=$(bktunnel -g -)` or
`bktunnel -g - | pass insert -e tunnel/privkey`. Recover the `pubkey` from a stored
private key anytime with `bktunnel -k @FILE -P`.

Throughout this README, `$CLIENT_PUBKEY` and `$SERVER_PUBKEY` stand for those
shared `pubkey` lines (each host pins the *other's*).

### 2. Run the server

```sh
bktunnel -r server -a 0.0.0.0:5560 -c 127.0.0.1:1883 \
    -k @/etc/tunnel/privkey -p "$CLIENT_PUBKEY"
```

Accepts TLS on `:5560`, forwards decrypted traffic to the local service on
`127.0.0.1:1883`.

### 3. Run the client

```sh
bktunnel -r client -a 127.0.0.1:5560 -c server.example:5560 \
    -k @/etc/tunnel/privkey -p "$SERVER_PUBKEY"
```

Accepts local plaintext on `127.0.0.1:5560`, encrypts it, and forwards to the
remote server. Point your application at `127.0.0.1:5560`.

## Usage examples

A tunnel has two ends. Generate a keypair on **each** host and hand its `pubkey`
line to the *other* host — the client pins the server's pubkey, and the server
pins the client's. Generation prints two labelled base64 lines, `privkey`
(secret) and `pubkey` (shareable):

```console
$ bktunnel -g -            # on the CLIENT host
privkey 5HeGHhu6ZFsSB1dYimWPan3r41txn87Q3jW6Z23tjP8=
pubkey  Iy7ML4xwxIi7B4Ez67yldQSF3nT/O1u3y4w389pdAGY=
```

```console
$ bktunnel -g -            # on the SERVER host
privkey og/wRdRkSp0BBehIuJcEHIU12agX3epVo8rVJSxf3i4=
pubkey  wwy/Nwo5y+eUPl7P+dv5CjT9fybiarNipZ+q+NZNsZg=
```

The examples below use the two **pubkeys** from above (each host keeps its own
`privkey` private):

```sh
CLIENT_PUBKEY=Iy7ML4xwxIi7B4Ez67yldQSF3nT/O1u3y4w389pdAGY=
SERVER_PUBKEY=wwy/Nwo5y+eUPl7P+dv5CjT9fybiarNipZ+q+NZNsZg=
```

You can also write the keypair to files instead of stdout: `-g FILE` writes the
private key to `FILE` (`0600`) and the public key to `FILE.pub` (`0644`), while a
bare `-g` prompts for a path (default `~/.bktunnel/id_ed25519`):

```sh
bktunnel -g ~/.bktunnel/id_ed25519   # writes that file and its .pub alongside
```

The `.pub` (and the `.crt`/`.key` below) are always written next to the path you
give `-g`; nothing is forced into `~/.bktunnel`. That directory is only the
*default* for a bare `-g` with no path. Writing to `~/.bktunnel/id_ed25519` is
handy because it is also where `-k` looks by default, so the key becomes this
host's identity with no extra flags.

#### Key type (`-t`)

`-g` mints an Ed25519 identity by default. Pass `-t p256` for an **ECDSA P-256**
(secp256r1 / prime256v1) identity instead:

```sh
bktunnel -g ~/.bktunnel/id_p256 -t p256
```

Ed25519 is the right choice for bktunnel-to-bktunnel tunnels. P-256 exists for
one case: a peer that must be a **browser or mobile client**, which cannot use an
Ed25519 client certificate (Firefox/NSS and Android's Conscrypt/Keystore won't
import an Ed25519 key). The two types interoperate freely — a P-256 client talks
to an Ed25519 server and vice versa — and a `-p` / `authorized_keys` set may
**mix** them: an Ed25519 pin decodes to 32 bytes and a P-256 pin to 33, so they
never collide. So you can keep every bktunnel node on Ed25519 and simply add a
browser's P-256 pubkey to the server's `authorized_keys`.

#### Standalone client cert (`--pem`, `--p12`)

Add `--pem` to a file-destination `-g` to also write `FILE.crt` (a PEM
certificate over the same key, `0644`) and `FILE.key` (the matching PKCS#8
private key, `0600`) beside `FILE`:

```sh
bktunnel -g ~/.bktunnel/id_ed25519 --pem   # + id_ed25519.crt and id_ed25519.key
```

`--pem` and `--p12` also work **without `-g`**, to export from an identity you
already have: point `-k` at the key file and they write the same files beside it,
minting no new key. Combine them freely.

```sh
# export both file sets from an existing key (no new key is generated):
bktunnel -k @~/.bktunnel/id_p256 --pem --p12   # + id_p256.crt/.key and id_p256.p12
```

This needs `-k` to name a **file** (a `@FILE` or the default identity file);
a literal, stdin, or `$TUNNEL_PRIVKEY` key has nowhere to write beside and errors.
With no tunnel options it exports and exits; with them it exports and then runs.
Like `-g`, it prompts before overwriting an existing export and refuses to clobber
one non-interactively (`rm` the file first, or answer `y`, to replace it).

These let an **OpenSSL-family client connect straight to a `bktunnel` server
without running the `bktunnel` proxy** — the server pins the bare public key,
which is identical across all four files, so the cert authenticates the same
identity:

```sh
# The server shares its base64 pubkey (the value you'd pass to -p). Convert it to
# curl's pin — sha256 of the Ed25519 SPKI, base64 — by prepending the fixed
# Ed25519 SPKI DER header (the same constant the bash tool uses):
PIN=$( { printf '302a300506032b6570032100' | xxd -r -p; base64 -d <<<"$SERVER_PUBKEY"; } \
  | openssl dgst -sha256 -binary | openssl base64 )

# --pinnedpubkey is enforced even with -k, so the pin — not a CA —
# authenticates the server, reproducing what bktunnel's -p does:
curl -k --pinnedpubkey "sha256//$PIN" \
  --cert ~/.bktunnel/id_ed25519.crt --key ~/.bktunnel/id_ed25519.key \
  https://server:5560/...
```

The `pubkey` you hand a `bktunnel` server operator is unchanged, so no
server-side change is needed. `--pem` is ignored when generating to stdout (`-g -`), which has no
file destination. The server presents its own pinned, non-CA certificate: `-k`
skips the CA check, and `--pinnedpubkey` authenticates it by key instead — a
mismatch aborts the request (`curl: (90) SSL: public key does not match pinned
public key`). Omit `--pinnedpubkey` for a quick connection that leaves the
server unauthenticated.

These files suit **OpenSSL-family clients** — `curl`, `openssl s_client`, and
most language TLS stacks. For a **browser or mobile** client, generate a
[**P-256**](#key-type--t) identity and add `--p12`, which writes `FILE.p12`, the
PKCS#12 bundle those platforms import, directly:

```sh
bktunnel -g ~/.bktunnel/id_p256 -t p256 --p12   # + id_p256.p12 (and .pub)
```

The bundle uses an **empty password** (import it and leave the password blank; see
[why](#why-the-p12-uses-an-empty-password)). `--p12` can be combined with
`--pem` if you also want the loose `.crt`/`.key`; alone it just adds the `.p12`.
An **Ed25519** identity can't be used this way: Firefox/NSS and Android refuse to
import an Ed25519 key from a PKCS#12 (*"The PKCS #12 operation failed for unknown
reasons"*) — the key type, not the packaging, is the blocker, which is exactly
why P-256 is offered (`--p12` warns if you pair it with `-t ed25519`). The server
just pins the client's P-256 pubkey (mixed into `authorized_keys`); its own
identity can stay Ed25519.

##### Why the `.p12` uses an empty password

A PKCS#12 password protects the private key inside the bundle, but that key is
the **same secret** already sitting unencrypted in `FILE` (and `FILE.key` with
`--pem`) — `bktunnel` stores private keys in the clear at rest, protected by file
mode (`0600`), not a passphrase. A passphrase on only the `.p12` copy would guard
one of several plaintext copies while leaving the others open, so it buys
nothing; the `.p12` is written `0600` like the rest.

So `--p12` uses the **empty password** — the field you leave blank at import.
Note this is *not* the same as a bundle with no cryptography at all: the file is
still encrypted and MAC'd (AES-256 / PBKDF2, SHA-256 MAC), just with a key
derived from the empty string. That matters because Firefox/NSS and Android
**reject** a truly unencrypted, MAC-less PKCS#12 (*"Failed to decode the file …
not in PKCS #12 format, has been corrupted, or the password … incorrect"*); a
well-formed bundle needs the MAC even when the password is empty. The upshot is
that the **import prompt** is answered once, with a blank field:

- **Firefox** asks for the *certificate backup* password when you import the
  `.p12` (Settings → Privacy & Security → Certificates → *Your Certificates* →
  *Import*). Leave it blank, click *OK*, and the key lands in Firefox's own
  certificate store. It is **not** asked again — not on later launches and not
  when a site requests the client cert. (What Firefox *may* still prompt for is
  the cert-**selection** dialog — *which* identity to present — and, only if you
  have set one, the browser's **Primary Password** that locks the whole NSS
  store; neither is the `.p12`'s blank password.)
- **macOS/iOS Keychain** and **Android** likewise consume the blank password at
  install and then treat the key like any other stored identity.

`FILE.key` is a **second at-rest copy of your private key** (the same secret as
`FILE`, PKCS#8-encoded), so it is written `0600` and is yours to protect and
shred like any key file — which is why `--pem` is opt-in rather than emitted by
every `-g`. It does not change the proxy's RAM-only runtime; these files exist
for a stock TLS client or server used *instead* of the `bktunnel` proxy.

##### Stable on-wire cert across restarts (`--cert`)

By default a running `bktunnel` proxy **mints a fresh carrier cert in RAM at every
start** — new random serial, new (randomized ECDSA) signature — and presents that.
Peers don't care: they pin the *public key* and ignore the rest, so the cert
changes but the identity doesn't. A **browser talking directly to a `bktunnel`
server** does care, though: its stored trust exception for that host is keyed on
the whole-cert **fingerprint**, so a cert that changes every restart makes the
browser re-prompt each time.

`--cert FILE` fixes that for the running tunnel: present `FILE` (a PEM cert — e.g.
the `FILE.crt` from `-g --pem`) on the wire verbatim instead of minting a new one:

```sh
# server identity + a persisted cert, generated once:
bktunnel -g ~/.bktunnel/id_p256 -t p256 --pem
# run the server presenting that same cert every time:
bktunnel -r server -a :5560 -c 127.0.0.1:8080 -k @~/.bktunnel/id_p256 \
  --cert ~/.bktunnel/id_p256.crt -p "p256 <client-pubkey>"
```

A **bare `--cert`** (no filename) derives `<keyfile>.crt` from the `-k` key file
(or the default identity file), so with the `--pem` naming you can just write
`-k @~/.bktunnel/id_p256 --cert` and it picks up `~/.bktunnel/id_p256.crt`. It
errors if the key came from a literal, stdin, or `$TUNNEL_PRIVKEY` (no file to
derive from).

Because the bytes are identical run to run, the browser's exception stays valid
across restarts. The cert's public key must match the identity key (`-k`), or the
pin a peer holds for you won't match what you present — `bktunnel` checks this at
startup and refuses a mismatched or unreadable file. This is opt-in and only about
the *server*-facing cert a browser sees; `bktunnel`-to-`bktunnel` links are
unaffected either way (they pin the key). It does **not** remove the initial trust
warning — the cert still has no CA and no SAN, so a browser prompts once — it only
stops that prompt from *recurring* on every restart. (Note this puts the public
cert on disk; the private key is unchanged, still `0600`, and `--pem` already
wrote a key copy there.)

##### Replacing the server proxy, too

The `.crt`/`.key` are a plain Ed25519 or P-256 identity, not client-specific — any TLS
tool can load them on **either** end. So you can equally drop the proxy on the
*server* side: point a stock TLS terminator (nginx, stunnel, socat, a Go
`tls.Listen`) at your backend, give it `FILE.crt`/`FILE.key` as its server
certificate, and a `bktunnel` *client* that pins the server's pubkey with `-p`
will accept it.

What you keep versus give up is about **which pin each role owns**. `bktunnel`
normally does two independent pins: the client authenticates the server (the
client's `-p`) and the server authenticates the client (the server's `-p`). The
`bktunnel` end you keep always still enforces its pin; the question is whether the
stock tool you drop in can reproduce the pin *its* role owns:

- **A stock client can reproduce the client's pin.** Authenticating a server by
  its public key is a normal client feature — `curl --pinnedpubkey`, or pinning
  the cert via `--cacert` — so a stock client can keep full mutual auth. If you
  instead tell it to skip verification (`curl -k`), you drop that pin *by
  choice*, and this becomes exactly as one-way as the server case below.
- **A stock server usually cannot reproduce the server's pin.** Authenticating a
  client by its bare public key is not something nginx/stunnel/etc. do — they
  verify clients against a CA — so on this side the client-authentication pin is
  dropped *by necessity*.

So neither replacement is inherently lossless: each collapses mutual
authentication to one-way unless the stock tool re-adds the pin its role owns.
The practical difference is only that client tools commonly can (pinning a
server's pubkey is a normal feature) while stock servers commonly cannot
(bare-pubkey client pinning is not). Replace **both** ends and you have left
`bktunnel`'s trust model entirely — it is then just two certs with no pinning.

### Server

Runs on the host with the real service. It accepts **TLS** from clients on `-a`,
forwards the decrypted stream to the local service on `-c`, and pins the
**client's** pubkey with `-p`.

```sh
# accept TLS on :5560, forward to a local MQTT broker; private key from a file
bktunnel -r server -a 0.0.0.0:5560 -c 127.0.0.1:1883 \
    -k @/etc/tunnel/privkey -p "$CLIENT_PUBKEY"

# pin several clients at once, from a file
bktunnel -r server -a 0.0.0.0:5560 -c 127.0.0.1:1883 \
    -k @/etc/tunnel/privkey -p @/etc/tunnel/peers.pub
```

A `peers.pub` file for `-p @FILE` is ssh-`authorized_keys`-style: one pin per
line as `[<type>] <base64> [comment]`. The `<type>` (`ed25519` or `p256`) is
optional — the key's length identifies it — and the two types may be mixed.
Blank lines, whole-line `#` comments, and any text after the key are ignored:

```
# client host
ed25519 Iy7ML4xwxIi7B4Ez67yldQSF3nT/O1u3y4w389pdAGY= alice@laptop
# backup client (a browser, so p256)
p256 AhOi5LVCZEdSfxpSyT/DJLfsTrINL+uIF7TzFOF1nwWE bob-phone
```

The server handles multiple clients concurrently — each connection gets its own
TLS session and its own connection to the `-c` service — and any client whose
pubkey is pinned may connect. Two caveats:

- The `-c` service must accept concurrent connections: N clients open N backend
  connections, so a single-connection service there becomes the bottleneck.
- There is no built-in connection cap, so a busy or misbehaving pinned peer can
  open many connections at once. Add a limit if that matters (stunnel has
  options for it; the Go build would need a semaphore).

### Client

Runs next to the application that needs the remote service. It accepts local
**plaintext** on `-a`, forwards it over **TLS** to the server on `-c`, and pins
the **server's** pubkey with `-p`. Point your application at the client's local
`-a` address.

```sh
# private key piped in on stdin
echo 5HeGHhu6ZFsSB1dYimWPan3r41txn87Q3jW6Z23tjP8= | \
    bktunnel -r client -a 127.0.0.1:5560 -c server.example:5560 -k - -p "$SERVER_PUBKEY"

# private key from the environment, sourced from a secrets store so the literal
# stays out of bktunnel's argv and shell history (the env itself is still
# readable via `ps e` / /proc, so this suits a trusted host)
TUNNEL_PRIVKEY=$(pass show client/privkey) \
    bktunnel -r client -a 127.0.0.1:5560 -c server.example:5560 -p "$SERVER_PUBKEY"
```

## Supplying the private key

`-k` selects *this* host's identity (its private key); pick exactly one source:

| Form         | Source                                                        |
|--------------|---------------------------------------------------------------|
| `-k PRIVKEY` | literal base64 (visible in `ps`/history — avoid)              |
| `-k -`       | read from stdin (prompts if stdin is a terminal)              |
| `-k @FILE`   | read from `FILE` (first line; a leading `privkey` label and/or a trailing `# …` comment are stripped) |
| *(omit `-k`)*| read `~/.bktunnel/id_ed25519` if present, else the `TUNNEL_PRIVKEY` environment variable |
| *(with `-g`)*| the freshly generated private key is used; any `-k` is ignored |

Lost the `pubkey` but still have the `privkey`? Recover it — the public key is
derived deterministically from the private key. `-P` accepts the private key
from any `-k` source (literal, `@FILE`, stdin via `-k -`, or `TUNNEL_PRIVKEY`),
prints the shareable `<type> <base64>` line, and exits:

```sh
bktunnel -k @/etc/tunnel/privkey -P     # from a file      -> <type> <base64>
pass show tunnel/privkey | bktunnel -k - -P   # from stdin  -> <type> <base64>
bktunnel -g - | bktunnel -k - -P        # generate, then show its pubkey
```

## Pinning peers with `-p`

`-p` takes the *other* host's public key (an optionally `<type>`-prefixed base64
line). Repeat it for multiple peers, or read a list from a file with `-p @FILE`
(ssh-`authorized_keys`-style: `[<type>] <base64> [comment]` per line; blank
lines, `#` comments, and text after the key ignored). Literals and `@FILE` may
be mixed, as may `ed25519` and `p256` pins.

```sh
bktunnel -r server -a 0.0.0.0:5560 -c 127.0.0.1:1883 \
    -k @/etc/tunnel/privkey -p @/etc/tunnel/peers.pub
```

If you pass no `-p` at all, `bktunnel` reads `~/.bktunnel/authorized_keys` (same
format), mirroring SSH — see [Default key files](#default-key-files-bktunnel).

## Default key files (`~/.bktunnel`)

Like SSH's `~/.ssh`, `bktunnel` keeps *at-rest* keys under `~/.bktunnel` and falls
back to them when the matching flag is omitted:

| File | Role | Used when |
|------|------|-----------|
| `~/.bktunnel/id_ed25519` | this host's private key (Ed25519) | `-k` is omitted |
| `~/.bktunnel/id_p256` | this host's private key (P-256) | `-k` is omitted and no `id_ed25519` |
| `~/.bktunnel/id_ed25519.pub` / `id_p256.pub` | this host's public key | written alongside; hand it to a peer |
| `~/.bktunnel/authorized_keys` | pinned peer public keys, ssh-style (`[<type>] <base64>` per line) | no `-p` is passed |

With `-k` omitted, `bktunnel` reads `id_ed25519` if present, otherwise `id_p256`
(one default identity per key type, ssh-style). Running `bktunnel -g` with no
`FILE` **at a terminal** prompts for a path (ssh-keygen style, defaulting to
`~/.bktunnel/id_ed25519`, or `~/.bktunnel/id_p256` under `-t p256` — press Enter
to accept, or type another path) and writes the pair there (directory `0700`,
private key `0600`, `.pub` `0644`). The private key is written
`<base64> # privkey <type>` and the `.pub` in ssh style as `<type> <base64>`;
the readers accept either, so the files still load cleanly. That same
`<type> <base64>` line is echoed to stdout (status goes to stderr), so you can
copy or pipe it without opening the `.pub`. To pin this host
on a peer, append its `id_ed25519.pub` line to that peer's
`~/.bktunnel/authorized_keys`.

With the files in place, a tunnel needs neither `-k` nor `-p`:

```sh
bktunnel -r client -a 127.0.0.1:5560 -c server.example:5560
```

Precedence: an explicit `-k` / `-p` always wins; when no `-k` is given,
`~/.bktunnel/id_ed25519` is preferred over `TUNNEL_PRIVKEY`.

## Generate and run in one step

If all the required tunnel options are supplied alongside `-g`, a fresh
identity is generated *and* used immediately:

```sh
bktunnel -g - -r client -a 127.0.0.1:5560 -c server.example:5560 -p "$SERVER_PUBKEY"
```

The other `-g` forms run afterward too: `-g FILE` writes the keypair
(`FILE` + `FILE.pub`) then runs, and a bare `-g` prompts for a path (default
`~/.bktunnel/id_ed25519`), writes the pair, then runs.

## Options

```
-r ROLE      "client" or "server"
-a ADDR      accept  address:port (local socket to listen on)
-c ADDR      connect address:port (destination to forward to)
-k PRIVKEY   this host's private key: literal | - (stdin) | @FILE (or $TUNNEL_PRIVKEY)
-p PUBKEY    peer public key (base64) or @FILE; repeatable
-g FILE      generate a keypair to FILE, then exit (or run); '-' = stdout —
             labelled privkey+pubkey to a terminal, bare privkey when piped
-t TYPE      key type for -g: ed25519 (default) | p256 (for a browser/mobile client cert)
--pem        also write <base>.crt + <base>.key (PEM); <base> = -g FILE, else the -k key file
--p12        also write <base>.p12 (empty-password PKCS#12 for browser/OS import; use p256)
--cert[=F]   present PEM cert F on the wire, not a fresh one (bare: derive <keyfile>.crt from -k)
-P           print this host's pubkey (derived from -k / $TUNNEL_PRIVKEY), then exit
-h           show help
```

## Configuration

Policy and structural choices are **hardcoded** near the top of the script
rather than exposed as flags — they define what the tool *is*. Several are
security-relevant (the Ed25519/P-256 DER headers, `verifyPeer`, the tmpfs run dir,
foreground mode). Read the inline comments before changing any of them.

## Running as a service

To run a tunnel under systemd, [`packaging/systemd/`](packaging/systemd/) has a
template unit (`bktunnel@.service`) plus config samples and setup instructions.
It runs one tunnel per instance, loads the private key via systemd credentials
(kept off argv and out of the environment), and is sandboxed with the usual
hardening directives — see
[`packaging/systemd/README.md`](packaging/systemd/README.md). The `.deb` installs
this unit to `/usr/lib/systemd/system/`.

### Why a *template* unit

The `@` in the filename makes it a **template**, not a directly-runnable
service. You never start `bktunnel@.service` itself — you start **instances** of
it, one per tunnel:

```sh
systemctl enable --now bktunnel@mqtt    # instance "mqtt"
systemctl enable --now bktunnel@vpn     # a second, independent tunnel
```

Each instance is a fully separate service — its own process, its own
`start`/`stop`/`status`, and its own journal (`journalctl -u bktunnel@mqtt`).

Everything after the `@` is the **instance name**, and systemd substitutes it
for the `%i` specifier when it instantiates the template. That's how one shipped
file drives many tunnels, each with config keyed on `%i`:

```
EnvironmentFile=/etc/bktunnel/%i.conf        # bktunnel@mqtt -> /etc/bktunnel/mqtt.conf
LoadCredential=privkey:/etc/bktunnel/%i.key  #              -> /etc/bktunnel/mqtt.key
… -p @/etc/bktunnel/%i.peers                 #              -> /etc/bktunnel/mqtt.peers
```

Enabling is per-instance too, so the package can't auto-enable anything: you
pick a name, drop in that instance's `/etc/bktunnel/<name>.{conf,key,peers}`,
then `systemctl enable --now bktunnel@<name>`. A tunnel is inherently
per-endpoint — you often run several — so a template yields N tunnels from one
unit with no copy-paste, the same pattern systemd uses for `getty@.service` and
`user@.service`.

### NixOS

On NixOS you don't install the unit file — use the flake's
`nixosModules.bktunnel`, which declares the same hardened service from your
configuration. It exposes one entry per tunnel under
`services.bktunnel.instances.<name>`:

```nix
# flake inputs: bktunnel.url = "github:zziigguurraatt/bktunnel";
# in your NixOS configuration:
imports = [ inputs.bktunnel.nixosModules.bktunnel ];
services.bktunnel.instances.mqtt = {
  role = "client";
  accept = "127.0.0.1:1883";
  connect = "server.example:5560";
  privateKeyFile = "/etc/bktunnel/mqtt.key";   # 0600; e.g. via agenix/sops-nix
  peers = [ "wwy/Nwo5y+eUPl7P+dv5CjT9fybiarNipZ+q+NZNsZg=" ];
};
```

Each instance becomes a `bktunnel-<name>` systemd service with the same
sandboxing as the packaged unit — see
[`packaging/nixos/module.nix`](packaging/nixos/module.nix).

## Building it into your own application

`bktunnel` runs as a proxy to wrap a service you *can't* change. But an
application you *do* control can build the same architecture in directly and
drop the proxy on that end. The pattern is small and self-contained; it's
exactly what the Go implementation does:

- give the endpoint a stable Ed25519 (or P-256) keypair, exchange the public keys
  out-of-band, and pin the peer's;
- present an Ed25519 (or P-256) cert carrying that key — CN set to `sha256(SPKI)[:40]`, and
  an issuer name distinct from the subject so it is **not** self-signed (a
  bash/stunnel peer pins you by that CN and rejects a self-signed leaf outright);
- in `crypto/tls`, set `InsecureSkipVerify: true` plus a `VerifyPeerCertificate`
  that accepts the peer only if its cert carries a pinned public key — and, on
  the server, `ClientAuth: tls.RequireAnyClientCert` for mutual auth.

That per-certificate verify hook is the simple path, and most stacks expose an
equivalent (the OpenSSL C API, Rust's rustls, and so on). If yours does **not**
— e.g. Python's standard-library `ssl` acting as a server — you must pin through
CA-chain building instead, which has a couple of non-obvious traps; see
[`conformance/`](conformance/) for a worked Python example and the pitfalls it
documents.

You don't need to control both ends. Because an embedded endpoint is
wire-compatible with a `bktunnel` proxy (same carrier-cert and CN
scheme), you can mix and match:

- **Both ends yours:** embed the pattern in each — no `bktunnel` process anywhere.
- **Only one end yours:** embed it there, and run `bktunnel` as the proxy on the
  end you can't modify; the two interoperate.

The two single-end shapes — your app terminates the pinned TLS itself, so there
is no local proxy and no plaintext loopback hop on that side:

**Native client** — your app dials out; the server end runs `bktunnel`:

```
  +--------------------------------------------------+
  | your CLIENT application   (embeds the pattern)   |
  |                                                  |
  | holds : CLIENT privkey   secret, in process      |
  | pins  : SERVER pubkey    from the server         |
  |                                                  |
  | dials pinned TLS to  server.example:5560         |
  +--------------------------------------------------+
         |
         v
      .-~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~-.
    .-(                                          )-.
    (  UNTRUSTED NETWORK                         )
    (                                            )
    (  only ciphertext crosses here:             )
    (  mutually-authenticated TLS with           )
    (  pinned public keys, so a MITM             )
    (  can neither read the stream nor           )
    (  impersonate either peer                   )
    '-(                                          )-'
      `-~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~-'
         |
         v
  +--------------------------------------------------+
  | SERVER host   (bktunnel -r server)               |
  |                                                  |
  | holds : SERVER privkey   secret, never shared    |
  | pins  : CLIENT pubkey    from client, via -p     |
  |                                                  |
  | -a 0.0.0.0:5560          listen  (TLS in)        |
  | -c 127.0.0.1:1883        dial    (plaintext out) |
  +--------------------------------------------------+
         |
         v   plaintext TCP (local)
  +--------------------------------------------------+
  | local service   127.0.0.1:1883   (e.g. MQTT)     |
  +--------------------------------------------------+
```

**Native server** — your app accepts directly; the client end runs `bktunnel`:

```
  +--------------------------------------------------+
  | your application                                 |
  +--------------------------------------------------+
         |
         v   plaintext TCP (local)
  +--------------------------------------------------+
  | CLIENT host   (bktunnel -r client)               |
  |                                                  |
  | holds : CLIENT privkey   secret, never shared    |
  | pins  : SERVER pubkey    from server, via -p     |
  |                                                  |
  | -a 127.0.0.1:5560        listen  (plaintext in)  |
  | -c server.example:5560   dial    (TLS out)       |
  +--------------------------------------------------+
         |
         v
      .-~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~-.
    .-(                                          )-.
    (  UNTRUSTED NETWORK                         )
    (                                            )
    (  only ciphertext crosses here:             )
    (  mutually-authenticated TLS with           )
    (  pinned public keys, so a MITM             )
    (  can neither read the stream nor           )
    (  impersonate either peer                   )
    '-(                                          )-'
      `-~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~-'
         |
         v
  +--------------------------------------------------+
  | your SERVER application   (embeds the pattern)   |
  |                                                  |
  | holds : SERVER privkey   secret, in process      |
  | pins  : CLIENT pubkey    from the client         |
  |                                                  |
  | -a 0.0.0.0:5560          accepts pinned TLS      |
  | handles the request in process (no service hop)  |
  +--------------------------------------------------+
```

`go/cmd/bktunnel/main.go` (`selfSignedCert`, `pinVerifier`, `tlsConfig`) is a
~40-line reference you can lift directly.

## Tests

Two test files drive traffic through a live tunnel — they start real server and
client processes, stream a 1 MiB binary payload through an echo backend, and
check every byte comes back unchanged:

- `go/cmd/bktunnel/interop_test.go` — **cross-implementation wire compatibility**
  across every bash/Go role pairing (bash server ↔ Go client, Go server ↔ bash
  client, and bash ↔ bash), plus a wrong-pin rejection. The bash side needs
  `stunnel`, `xxd`, `openssl`, and the repo-root `bktunnel` script; if any is
  missing these tests **fail** rather than skipping, so a green run always means
  interop was actually exercised.
- `go/cmd/bktunnel/e2e_test.go` — the **Go implementation on its own** (Go server
  ↔ Go client, plus a Go-only wrong-pin rejection). These need only the Go
  toolchain — no stunnel or bash script — so they run everywhere, including CI
  and any box without stunnel.
- `conformance/bktunnel.py` + `go/cmd/bktunnel/conformance_test.go` — a **third,
  independent implementation** (minimal Python 3: stdlib `ssl` + the
  `cryptography` package) driven as both client and server against the bash and
  Go tools, demonstrating the wire is stock mutual-TLS that any TLS stack can
  speak. Gated behind a build tag and its own `python3`/`cryptography`
  dependency, so it stays out of the default `make test`; run it explicitly.

```sh
make test            # whole Go suite (bash/Go interop + Go-only), verbose
make test-interop    # only the cross-implementation interop tests, verbose
make test-go         # only the Go-only end-to-end tests, verbose
make test-conformance # opt-in Python third-implementation probe (needs python3 + cryptography)
```

Every case generates fresh keypairs and asserts the payload round-trips
byte-for-byte; the rejection cases confirm a mismatched `-p` pin stops traffic.

### Poke a tunnel by hand with `netcat`

The automated tests wire up an in-process client and echo server. To watch a
tunnel move bytes yourself, stand one up on a single host with `nc` at both
ends. Use four terminals (or background the middle ones with `&`):

```sh
# 1. two identities, each pinning the other
bktunnel -g client.key
bktunnel -g server.key
CLIENT_PUBKEY=$(bktunnel -k @client.key -P | awk '{print $NF}')
SERVER_PUBKEY=$(bktunnel -k @server.key -P | awk '{print $NF}')

# 2. a stand-in service: netcat listening on :7000
nc -l 127.0.0.1 7000

# 3. server tunnel: accept TLS on :5560, forward plaintext to the nc service
bktunnel -r server -a 127.0.0.1:5560 -c 127.0.0.1:7000 \
    -k @server.key -p "$CLIENT_PUBKEY"

# 4. client tunnel: accept local plaintext on :6000, forward over TLS
bktunnel -r client -a 127.0.0.1:6000 -c 127.0.0.1:5560 \
    -k @client.key -p "$SERVER_PUBKEY"

# 5. talk to the client's local port
nc 127.0.0.1 6000
```

Whatever you type into the terminal-5 `nc` travels client → TLS → server → the
terminal-2 `nc` and prints there; since `nc` and the tunnel are both
bidirectional, typing into terminal 2 comes back to terminal 5.

To reproduce the automated byte-for-byte check by hand, leave the two tunnels
(3 and 4) running, replace the service `nc` with a capturing one, and push a
file through the client end:

```sh
head -c 1M /dev/urandom > in.bin
nc -l 127.0.0.1 7000 > out.bin &     # service: capture what arrives
nc -N 127.0.0.1 6000 < in.bin        # client: send the file, half-close at EOF
cmp in.bin out.bin && echo "tunnel preserved every byte"
```

Swapping in a wrong `-p` on either tunnel is the negative test: the handshake
fails, so nothing reaches the far `nc`.

> `nc` flag spellings vary by flavor. These use OpenBSD `nc` (Debian/Ubuntu's
> `netcat-openbsd`, and macOS): `-l host port` to listen, `-N` to half-close on
> EOF. GNU `netcat` spells them `-l -p port` and `-q 0`.

## Trust models: who authenticates whom

With `bktunnel` running on **both** ends, its default is **mutual** authentication
— each side pins the other with the `-p` option, or the default
`authorized_keys` file. But the pieces (each side's pin, and the [`--pem`](#standalone-client-cert---pem)
files that let a stock tool stand in for a proxy) also let you build one-way
arrangements on purpose. What a party gains is confidence that there is **no
man-in-the-middle (MITM)** on the connection. Who gets that confidence depends
on who authenticates whom.

| Who authenticates whom | Client sure: no MITM? | Server sure: no MITM? | What breaks it | Notes |
|---|---|---|---|---|
| **Mutual** — each authenticates the other | ✅ Yes | ✅ Yes | **Pinned:** either side's private key is leaked. **CA-signed:** additionally, any one rogue/compromised CA can forge either identity. | Neither side trusts the other to authenticate; **both** have data to lose. |
| **Client authenticates server** only | ✅ Yes | ❌ No | **Pinned:** the server's private key is leaked. **CA-signed:** additionally, any one rogue/compromised CA. | The server can't tell the client from an interposer. Because the client is the sole authenticator, any MITM-exposable data is treated as the **client's** risk, not the server's. Normal web browsing is the CA-signed instance of this case. |
| **Client authenticates server + shared secret — unknown client** | ✅ Yes | ❌ No | **Pinned:** the server's private key is leaked. **CA-signed:** additionally, any one rogue/compromised CA. **Either variant:** a leaked password lets someone pose as the client. | Normal web login. The server can't assume an arbitrary client verified it, so it can't conclude no-MITM — and thus can't confirm its peer is the client rather than an impostor; MITM-exposable data is the **client's** risk. |
| **Client authenticates server + shared secret — known client** | ✅ Yes | ✅ Implicitly, if it trusts the client authenticates the server | **Pinned:** the server's private key is leaked. **CA-signed:** additionally, any one rogue/compromised CA. **Either variant:** a leaked password lets someone pose as the client. | The server trusts this known client pins it (blocking a relaying MITM), so a valid password implies a direct connection ⇒ no MITM. |
| **Server authenticates client** only | ❌ No | ✅ Yes | **Pinned:** the client's private key is leaked. **CA-signed:** additionally, any one rogue/compromised CA. | Server needs to know the far end is the real client. |
| **Server authenticates client + shared secret — unknown server** | ❌ No | ✅ Yes | **Pinned:** the client's private key is leaked. **CA-signed:** additionally, any one rogue/compromised CA. **Either variant:** a leaked secret lets an impostor server fool the client. | Without trusting the server's behavior, the client can't rule out a relay obtaining the secret from the server, so recognizing it confirms neither no-MITM nor that its peer is the real server rather than an impostor. |
| **Server authenticates client + shared secret — known server** | ✅ Implicitly, if it trusts the server authenticates clients | ✅ Yes | **Pinned:** the client's private key is leaked. **CA-signed:** additionally, any one rogue/compromised CA. **Either variant:** a leaked secret lets an impostor server fool the client. | The client trusts this known server reveals the secret only to the authenticated client (blocking a relay), so verifying the secret gives **implicit** no-MITM without pinning the server. |

**Mutual — both sides authenticate each other.** Each end pins the other's
public key, so each authenticates the other and — because a MITM can present
neither pinned key — **both** ends have confidence there is no MITM. Use this
when neither side trusts the other to authenticate and **both** stand to lose if
their data is exposed to a MITM. This is the default when both ends run with
`-p` set.

**Client authenticates the server only.** The client pins the server; the server
does not pin the client. The **client** knows there is no MITM — it reached the
exact server it pinned. The **server does not**: it cannot tell whether the bytes
arrived straight from the client or through an interposer. This is the model of
**normal web browsing**: your browser authenticates the website (there, via a
CA-signed certificate rather than a pin) while the site does not authenticate
your browser at the TLS layer.

Note that trusting CA-signed certificates instead of pinning is **weaker** than
a pin. It requires trusting **every** CA in the browser's root store to be
honest and uncompromised — the guarantee is only as strong as the *least*
trustworthy CA. If at any time **one** CA anywhere in the world is breached,
coerced, or goes rogue, it can mint a valid-looking certificate for your server,
and the client will accept the MITM presenting it — the whole trust chain breaks
on that single failure. A pin trusts exactly one key, so it has no such weak
link.

**Client authenticates the server, plus a shared secret.** As above, the client
pins the server, and additionally hands the server a shared secret (e.g. a
password). What the server gains depends on whether the client is **known** to
it. For an **unknown** client (normal web login), a valid password proves only
that the real client's secret entered the chain — not that the server's actual
peer *is* the client. Unable to rule out a MITM, the server can't exclude that
its peer is an impostor that relayed or replayed the password, so it confirms
neither no-MITM nor identity, and treats any MITM-exposable data as the
**client's** risk. For a **known** client — one the
server trusts, out of band, to pin the server — the server gains **implicit**
no-MITM assurance: because that client would refuse a server it can't verify, a
relaying MITM can't sit between them, so a valid password implies a direct
connection.

**Server authenticates the client only.** The server pins the client; the client
does not pin the server. The **server** knows there is no MITM — the far end
proved possession of the pinned key. The **client does not** get that assurance
from the protocol: authenticating *itself* to the far end says nothing about
*who* the far end is, so an impostor server could sit in front of the client
undetected. For the client to gain assurance, the server must prove itself to the
client too — the next case.

**Server authenticates the client, plus a shared secret.** The mirror of the
case above, with roles swapped: the server pins the client and presents it a
pre-shared secret (e.g. an anti-phishing phrase) only the real server knows. What
the client gains depends on whether the server is **known** to it. For a **known** server —
one the client trusts, out of band (e.g. it physically owns the server), to
reveal the secret only to the authenticated client — verifying the secret gives
**implicit** no-MITM assurance without ever pinning the server: a terminating
impostor never had the secret, and a relaying one can't authenticate as the
pinned client to obtain it. For an **unknown** server the client has no such
trust — it can't rule out that a relay obtained the secret — so seeing the
correct secret proves neither no-MITM nor the server's identity: its peer could
be an impostor relaying the genuine secret. Both ingredients are load-bearing: without the
secret a terminating impostor fools the client; without the server authenticating
the client (and the client trusting that it does) a relaying impostor can obtain
the secret.

## Security notes

- Prefer `-k @FILE` (permissions `0600`, owner-only) or `TUNNEL_PRIVKEY` over a
  literal `-k PRIVKEY`, which leaks the private key into `ps` output and shell
  history.
- If you generate or store the private key with `-g FILE` / `-k @FILE` — or
  export it with `--pem`, which writes a second copy as `FILE.key` — those files
  are your responsibility: give them permissions `0600` (owner-only), ideally on
  a RAM-backed or encrypted path. The RAM-only property covers only the tool's
  derived runtime material, not your private key at rest.
- The tool's derived runtime material (bash) only exists under `/dev/shm` for
  the lifetime of the process and is
  [shredded](https://www.gnu.org/software/coreutils/manual/html_node/shred-invocation.html)
  on exit — keep `CFG_RUNDIR_BASE` RAM-backed. The Go build keeps it in memory
  and writes nothing.
- Certificate validity (`CFG_CERT_DAYS`) is deliberately long and cosmetic:
  trust is pinned to the key, not gated on expiry.

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 Lightning Labs.
