#!/usr/bin/env python3
"""Minimal bktunnel wire-conformance implementation in Python 3.

This is NOT a maintained implementation. It is a conformance probe: it proves
the bktunnel wire is plain mutual-TLS whose trust is a raw Ed25519 public-key
pin, carried in a throwaway (non-self-signed) X.509 cert - so any stock TLS
stack can interoperate with the bash+stunnel and Go implementations. It speaks
BOTH roles (client and server).

TLS is the standard-library `ssl` module. Certs are built in-process with the
`cryptography` package (the standard library has no Ed25519 and cannot mint or
sign a certificate); this deliberately avoids shelling out to `openssl`.

How pinning works here (matching the other two implementations):
  * Our identity cert is NON-self-signed: subject CN = sha256(SPKI DER)[:40]
    (the same scheme the bash `cn()` uses), issuer = a fixed name distinct from
    the subject, signed by our own key. A verifying stunnel peer then reports
    "unable to get local issuer certificate" (tolerated -> it matches us by
    pinned pubkey) instead of "self-signed certificate" (rejected outright).
  * As a CLIENT we disable the stdlib's CA check (CERT_NONE) and instead compare
    the server leaf's public key to our pins after the handshake. Our client
    leaf's issuer is LEAF_ISSUER (== the pin-anchor subject; see below).
  * As a SERVER we cannot use a post-handshake check (requesting a client cert
    forces CA validation, and stdlib exposes no per-cert verify callback), so we
    turn each pinned pubkey into a stand-in trust anchor: a cert whose subject is
    the peer leaf's issuer name (LEAF_ISSUER), carrying the pinned public key,
    loaded with VERIFY_X509_PARTIAL_CHAIN (Python 3.10+). The client's leaf then
    chains to that anchor by signature, so only the pinned key verifies. Our own
    server leaf uses a DIFFERENT issuer (SERVER_ISSUER) so OpenSSL does not
    auto-append an anchor to the chain we send (that would break the peer's
    verification of us).

Wire flags mirror the bash tool: -r role, -a accept host:port, -c connect
host:port, -k base64-seed|@FILE, -p base64-pubkey|@FILE (repeatable).

Note: stdlib `ssl` loads the cert/key only from files, so the key must briefly
touch a file; like the bash tool it uses a RAM-backed tmpfs (/dev/shm) when
available and scrubs it right after loading, so it never hits persistent storage.
(Go needs no file at all.)
"""
import argparse
import base64
import datetime
import hashlib
import os
import shutil
import socket
import ssl
import sys
import tempfile
import threading

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption)

# A CLIENT leaf is issued by (name only) LEAF_ISSUER, which is also the subject of
# the stand-in pin anchors a server loads to verify clients. A SERVER leaf uses a
# DIFFERENT issuer name on purpose: the server has anchors named LEAF_ISSUER in
# its context, so if its own leaf's issuer were LEAF_ISSUER too, OpenSSL's
# auto-chain would append a (wrong-key) anchor to the server's SENT chain — the
# peer would then verify our leaf against that anchor's key and reject it with
# "certificate signature failure". See main().
LEAF_ISSUER = "bktunnel-issuer"      # client leaf issuer + pin-anchor subject
SERVER_ISSUER = "bktunnel-endpoint"  # server leaf issuer; MUST differ from LEAF_ISSUER


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def load_seed(spec):
    """-k value: base64 32-byte seed, or @FILE holding it (optional '# ...')."""
    if spec.startswith("@"):
        with open(spec[1:]) as f:
            spec = f.read()
    seed = base64.b64decode(spec.split("#", 1)[0].strip())
    if len(seed) != 32:
        sys.exit("privkey must decode to 32 bytes")
    return seed


def load_pins(specs):
    """-p values: base64 pubkeys and/or @FILEs of them (one per line)."""
    pins = set()
    for spec in specs:
        if spec.startswith("@"):
            with open(spec[1:]) as f:
                lines = f.read().splitlines()
        else:
            lines = [spec]
        for ln in lines:
            ln = ln.split("#", 1)[0].strip()
            if not ln:
                continue
            raw = base64.b64decode(ln)
            if len(raw) != 32:
                sys.exit("pin must decode to 32 bytes: %r" % ln)
            pins.add(raw)
    return pins


def _validity():
    now = datetime.datetime.utcnow()
    return now - datetime.timedelta(hours=1), now + datetime.timedelta(days=3650)


def cn_for(pub):
    spki = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(spki).hexdigest()[:40]


def identity_cert(seed, issuer_cn):
    """Return (cert_pem, key_pem) for a non-self-signed cert over the seed key."""
    key = Ed25519PrivateKey.from_private_bytes(seed)
    nb, na = _validity()
    cert = (x509.CertificateBuilder()
            .subject_name(_name(cn_for(key.public_key()))).issuer_name(_name(issuer_cn))
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(nb).not_valid_after(na)
            .sign(key, None))  # Ed25519 signs with algorithm=None
    return (cert.public_bytes(Encoding.PEM),
            key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))


def anchor_pem(pin_raw, signer):
    """A stand-in trust anchor carrying a pinned pubkey, subject == LEAF_ISSUER
    (the peer leaf's issuer name). Signed by a throwaway key; loaded with
    partial-chain, so OpenSSL trusts it by presence, not by its own signature."""
    nb, na = _validity()
    name = _name(LEAF_ISSUER)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(Ed25519PublicKey.from_public_bytes(pin_raw)).serial_number(1)
            .not_valid_before(nb).not_valid_after(na)
            # Must be a valid CA or OpenSSL rejects it as "invalid CA certificate"
            # when it uses this anchor to verify the peer's leaf.
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=True, crl_sign=False,
                encipher_only=False, decipher_only=False), critical=True)
            .sign(signer, None))
    return cert.public_bytes(Encoding.PEM)


def peer_pub(sslsock):
    """Raw Ed25519 public key from the peer's leaf cert, or None."""
    der = sslsock.getpeercert(binary_form=True)
    if not der:
        return None
    pub = x509.load_der_x509_certificate(der).public_key()
    if not isinstance(pub, Ed25519PublicKey):
        return None
    return pub.public_bytes(Encoding.Raw, PublicFormat.Raw)


def client_ctx(certfile, keyfile):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we pin the server's pubkey ourselves
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile, keyfile)
    return ctx


def server_ctx(certfile, keyfile, pins):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile, keyfile)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    signer = Ed25519PrivateKey.generate()  # throwaway anchor signer
    anchors = b"".join(anchor_pem(p, signer) for p in pins)
    ctx.load_verify_locations(cadata=anchors.decode("ascii"))  # in memory
    return ctx


def splice(src, dst):
    """Copy src -> dst until EOF, then half-close dst so the peer sees EOF."""
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def relay(a, b):
    t = threading.Thread(target=splice, args=(a, b), daemon=True)
    t.start()
    splice(b, a)
    t.join()
    a.close()
    b.close()


def client_conn(plain, connect, ctx, pins):
    try:
        raw = socket.create_connection(connect)
    except OSError as e:
        sys.stderr.write("dial %s: %s\n" % (connect, e))
        plain.close()
        return
    try:
        tls = ctx.wrap_socket(raw)
    except ssl.SSLError as e:
        sys.stderr.write("TLS handshake: %s\n" % e)
        plain.close()
        raw.close()
        return
    pk = peer_pub(tls)
    if pk is None or pk not in pins:
        sys.stderr.write("server public key does not match any pin\n")
        plain.close()
        tls.close()
        return
    relay(plain, tls)


def server_conn(raw, connect, ctx, pins):
    try:
        tls = ctx.wrap_socket(raw, server_side=True)  # verifies client via anchors
    except ssl.SSLError as e:
        sys.stderr.write("client TLS/verify: %s\n" % e)
        raw.close()
        return
    pk = peer_pub(tls)  # defence in depth; the anchor check already gated this
    if pk is None or pk not in pins:
        sys.stderr.write("client public key does not match any pin\n")
        tls.close()
        return
    try:
        backend = socket.create_connection(connect)
    except OSError as e:
        sys.stderr.write("dial %s: %s\n" % (connect, e))
        tls.close()
        return
    relay(tls, backend)


def main():
    ap = argparse.ArgumentParser(description="minimal bktunnel conformance impl")
    ap.add_argument("-r", dest="role", required=True, help="client|server")
    ap.add_argument("-a", dest="accept", required=True, help="host:port to listen on")
    ap.add_argument("-c", dest="connect", required=True, help="host:port to forward to")
    ap.add_argument("-k", dest="priv", required=True, help="base64 seed or @FILE")
    ap.add_argument("-p", dest="pins", action="append", default=[], help="peer pubkey b64 or @FILE")
    args = ap.parse_args()

    if args.role not in ("client", "server"):
        sys.exit("-r must be 'client' or 'server'")
    pins = load_pins(args.pins)
    if not pins:
        sys.exit("at least one -p pin is required")

    ah, aport = args.accept.rsplit(":", 1)
    ch, cport = args.connect.rsplit(":", 1)
    connect = (ch, int(cport))

    # A client's leaf is issued by LEAF_ISSUER (== the pin-anchor subject) so a
    # python server can chain-verify it; a server's leaf must use a different
    # issuer, or OpenSSL auto-appends a wrong-key anchor to its sent chain.
    leaf_issuer = LEAF_ISSUER if args.role == "client" else SERVER_ISSUER
    # stdlib ssl loads the cert/key only from files (not memory), so they must
    # briefly exist as files. Put them on a RAM-backed tmpfs (/dev/shm) when there
    # is one, so the private key never touches persistent storage - matching the
    # bash tool. Fall back to the default temp dir where there's no /dev/shm (e.g.
    # macOS). (The Go implementation needs no file at all.)
    ram = "/dev/shm" if os.path.isdir("/dev/shm") else None
    d = tempfile.mkdtemp(prefix="bktunnel-py.", dir=ram)
    keyfile = os.path.join(d, "node.key")
    try:
        cert_pem, key_pem = identity_cert(load_seed(args.priv), leaf_issuer)
        certfile = os.path.join(d, "node.crt")
        with open(certfile, "wb") as f:
            f.write(cert_pem)
        with open(os.open(keyfile, os.O_WRONLY | os.O_CREAT, 0o600), "wb") as f:
            f.write(key_pem)
        ctx = client_ctx(certfile, keyfile) if args.role == "client" \
            else server_ctx(certfile, keyfile, pins)
    finally:
        # ssl has the key in memory now; scrub the key file (best-effort, guards
        # against tmpfs being swapped out) and remove the dir.
        try:
            with open(keyfile, "r+b") as f:
                n = f.seek(0, os.SEEK_END)
                f.seek(0)
                f.write(b"\x00" * n)
                f.flush()
        except OSError:
            pass
        shutil.rmtree(d, ignore_errors=True)

    handler = client_conn if args.role == "client" else server_conn
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind((ah, int(aport)))
    lsock.listen(16)
    while True:
        conn, _ = lsock.accept()
        threading.Thread(target=handler, args=(conn, connect, ctx, pins),
                         daemon=True).start()


if __name__ == "__main__":
    main()
