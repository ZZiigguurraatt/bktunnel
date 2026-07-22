# Wire-conformance probe (Python)

`bktunnel.py` is a minimal Python 3 implementation of the bktunnel wire. It is
**not** a maintained implementation — it exists to prove the wire is plain
mutual-TLS with a raw Ed25519 public-key pin, so any stock TLS stack can
interoperate with the bash+stunnel and Go implementations. It speaks **both
roles** (client and server).

## Dependencies

- Python **3.10+** (needs `ssl.VERIFY_X509_PARTIAL_CHAIN` for the server role).
- The [`cryptography`](https://pypi.org/project/cryptography/) package
  (`pip install cryptography`) — the standard library has no Ed25519 and cannot
  mint a certificate. TLS itself is stdlib `ssl`; certs are built in-process, so
  it never shells out to `openssl`.

## How it pins

Trust is the peer's raw Ed25519 public key. The identity cert is non-self-signed
(subject `CN=sha256(SPKI)[:40]`, a distinct issuer name) so a stunnel peer
accepts it. As a **client** it disables the stdlib CA check and compares the
server leaf's public key to the pins after the handshake. As a **server** it
turns each pinned key into a stand-in trust anchor (subject = the leaf's issuer
name, carrying the pinned key) loaded with `VERIFY_X509_PARTIAL_CHAIN`, so the
client's leaf verifies only if it was signed by the pinned key.

stdlib `ssl` loads the cert/key only from files (not memory), so the private key
must briefly touch a file. Like the bash tool, it goes on a RAM-backed tmpfs
(`/dev/shm` when present), is scrubbed, and removed right after `ssl` loads it —
so it never touches persistent storage. (Go needs no file at all; without
`/dev/shm`, e.g. macOS, it falls back to the default temp dir.)

## Pitfalls — why the server role is fiddly

These are **implementation** pitfalls, not wire issues, and they are unique to
TLS stacks (like stdlib `ssl`) that have **no per-certificate verify callback**.
The client role is trivial (pin the peer's pubkey after the handshake). The
server role has to verify the client cert through OpenSSL chain-building, and the
stand-in-anchor + `partial_chain` trick above has two traps that cost real
debugging:

1. **The anchor must be a valid CA** — `basicConstraints CA:TRUE` (+
   `keyCertSign`), or verification fails with `invalid CA certificate`.
2. **The server's own leaf must not be issued by the anchor's name.** The anchor
   subject is `bktunnel-issuer` so it can vouch for client leaves (whose issuer
   is `bktunnel-issuer`). If the server's *own* leaf were also issued by
   `bktunnel-issuer`, OpenSSL auto-appends a wrong-key anchor from the verify
   store to the chain the server **sends**, and the peer then verifies the server
   leaf against that anchor's key → `certificate signature failure`. So server
   leaves here use a distinct issuer (`bktunnel-endpoint`); client leaves keep
   `bktunnel-issuer`.

The bash (stunnel) and Go implementations pin by comparing public keys in a
verify callback and never build a synthetic CA, so they sidestep both. If your
stack has a verify hook (Go `crypto/tls`, the OpenSSL C API, Rust rustls, …),
prefer it — it's simpler and has none of these pitfalls.

## Run it directly

```sh
# client: plaintext in on :1080, TLS out to the server
python3 conformance/bktunnel.py -r client \
    -a 127.0.0.1:1080 -c server.example:5560 \
    -k @/path/to/id_ed25519 -p <peer-pubkey-base64>

# server: TLS in on :5560, plaintext out to a local backend
python3 conformance/bktunnel.py -r server \
    -a 0.0.0.0:5560 -c 127.0.0.1:1883 \
    -k @/path/to/id_ed25519 -p <peer-pubkey-base64>
```

## Run it via the test harness

The Go interop harness drives this probe as client and as server, against the
bash and Go implementations. It is gated behind a build tag (and needs
`python3` + `cryptography`, plus `stunnel`/`xxd` for the bash pairings), so the
default `make test` never touches it:

```sh
make test-conformance
```
