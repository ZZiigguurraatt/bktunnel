// Command bktunnel is a pinned-identity, mutual-auth TLS tunnel.
//
// It is a from-scratch reimplementation of the bktunnel bash script that
// drops stunnel and openssl: the Ed25519 identity key stays in process memory,
// a carrier certificate is minted in RAM purely so there is
// something to present during the handshake, and trust is a raw public-key
// compare in VerifyPeerCertificate. No CA, and a running tunnel keeps its key
// in memory — nothing to shred. (The ~/.bktunnel key files are optional at-rest
// storage, read once at startup; see -g/-k/-p.)
//
// The command-line contract matches the bash tool: -r/-a/-c/-k/-p/-g, the
// "privkey <b64>" / "pubkey <b64>" key format, and the TUNNEL_PRIVKEY
// environment variable. The two implementations are designed to be
// wire-compatible: a bash node and a Go node interoperate, because Go presents
// an Ed25519 cert (issuer name distinct from subject, so not self-signed) whose
// CN uses the same sha256(SPKI)[:40] scheme the bash side pins on. Interop is
// exercised by interop_test.go (needs stunnel).
package main

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// certDays is how long the in-memory carrier cert is valid. Cosmetic: trust is
// pinned by key, not gated on expiry, so it is deliberately long.
const certDays = 3650

// leafIssuerCN is the issuer name stamped on our identity cert. It only has to
// differ from the subject (the key-hash CN) and never appear in a peer's pin
// set, so the cert is NOT self-signed: a verifying stunnel peer then reports
// "unable to get local issuer certificate" (which it tolerates before matching
// us by pinned public key) instead of "self-signed certificate" (which it
// rejects outright). Mirrors the bash tool's CFG_LEAF_ISSUER.
const leafIssuerCN = "bktunnel-issuer"

// Build metadata, injected by the Makefile via -ldflags "-X main.<name>=...".
// Empty under a plain `go build` / `go install`; `--version` omits empty lines.
var (
	BuildTime string
	GitRev    string
	GitTime   string
	GitDirty  string
)

func printVersion() {
	fmt.Println("bktunnel (Go implementation)")
	fmt.Printf("go:     %s\n", runtime.Version())
	if GitRev != "" {
		rev := GitRev
		if GitDirty != "" {
			rev += "-" + GitDirty // e.g. "a1b2c3d-dirty" (git's convention)
		}
		fmt.Printf("git:    %s\n", rev)
	}
	if BuildTime != "" {
		fmt.Printf("built:  %s\n", BuildTime)
	}
}

// ---- key material ----
//
// An identity is a fresh Ed25519 seed or an ECDSA P-256 scalar — either way 32
// raw secret bytes, stored base64 (the bash tool's key format). Public keys
// travel as "bare" bytes: 32 for Ed25519, a 33-byte compressed point for P-256,
// so the decoded length alone tells the two apart (that is how a single
// authorized_keys file mixes both). Private keys are both 32 bytes, so their
// algorithm rides an "ed25519"/"p256" label that -g writes and -k accepts,
// defaulting to Ed25519 when absent (backward compatibility).

const (
	algoEd25519 = "ed25519"
	algoP256    = "p256"
)

// defaultKeyName is the at-rest identity filename for a key type (ssh-style:
// id_ed25519, id_p256), used as the bare-`-g` save default. defaultKeyNames is
// the search order the no-`-k` default resolution tries.
func defaultKeyName(algo string) string { return "id_" + algo }

var defaultKeyNames = []string{defaultKeyName(algoEd25519), defaultKeyName(algoP256)}

// generateKey mints a fresh identity key of the named algorithm.
func generateKey(algo string) (crypto.Signer, error) {
	switch algo {
	case algoEd25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	case algoP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	return nil, fmt.Errorf("unknown key type %q (want %s or %s)", algo, algoEd25519, algoP256)
}

// privSeed returns the algorithm label and the raw 32 secret bytes for a signer
// — the bare private key bktunnel stores base64.
func privSeed(priv crypto.Signer) (algo string, seed []byte, err error) {
	switch k := priv.(type) {
	case ed25519.PrivateKey:
		return algoEd25519, k.Seed(), nil
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() {
			return "", nil, errors.New("only P-256 ECDSA keys are supported")
		}
		b := make([]byte, 32)
		k.D.FillBytes(b)
		return algoP256, b, nil
	}
	return "", nil, errors.New("unsupported private key type")
}

// decodePriv rebuilds a signer from the algorithm label and base64 32-byte seed.
func decodePriv(algo, b64 string) (crypto.Signer, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, fmt.Errorf("private key: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("private key must be 32 bytes, got %d", len(raw))
	}
	switch algo {
	case algoEd25519:
		return ed25519.NewKeyFromSeed(raw), nil
	case algoP256:
		c := elliptic.P256()
		d := new(big.Int).SetBytes(raw)
		if d.Sign() == 0 || d.Cmp(c.Params().N) >= 0 {
			return nil, errors.New("p-256 private scalar out of range")
		}
		priv := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: c}, D: d}
		priv.X, priv.Y = c.ScalarBaseMult(raw)
		return priv, nil
	}
	return nil, fmt.Errorf("unknown key type %q", algo)
}

// barePub is the wire/pin form of a public key: Ed25519 -> 32 raw bytes; ECDSA
// P-256 -> 33-byte compressed point. The length distinguishes the two.
func barePub(pub crypto.PublicKey) ([]byte, error) {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return []byte(k), nil
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, errors.New("only P-256 ECDSA keys are supported")
		}
		return elliptic.MarshalCompressed(k.Curve, k.X, k.Y), nil
	}
	return nil, errors.New("unsupported public key type")
}

// decodePub validates a bare base64 public key and returns its wire bytes,
// dispatching on decoded length: 32 -> Ed25519, 33 -> P-256 compressed point.
func decodePub(b64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, fmt.Errorf("pubkey: %w", err)
	}
	switch len(raw) {
	case ed25519.PublicKeySize: // 32
		return raw, nil
	case 33:
		if x, _ := elliptic.UnmarshalCompressed(elliptic.P256(), raw); x == nil {
			return nil, errors.New("invalid P-256 compressed public key")
		}
		return raw, nil
	}
	return nil, fmt.Errorf("pubkey must be 32 (ed25519) or 33 (p-256) bytes, got %d", len(raw))
}

// identityCert mints an in-memory carrier cert over the identity key. Nothing is
// written to disk. Its CN is sha256(SPKI)[:40] — the same key-hash scheme the
// bash tool pins on. Crucially it is NOT self-signed: the issuer name is
// leafIssuerCN, distinct from the subject, so a verifying stunnel peer treats it
// as "issuer not found" (tolerated) and pins us by public key, rather than
// rejecting a self-signed leaf outright. We still sign with our own key; only
// the issuer NAME differs from the subject (a self-signed cert sets them equal).
func identityCert(priv crypto.Signer) (tls.Certificate, error) {
	der, err := certDER(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}

// certDER mints an X.509 certificate over the identity key and returns its DER
// bytes. It is deliberately NOT self-signed: the subject CN is sha256(SPKI)[:40]
// (the bash tool's key-hash scheme) while the issuer NAME is leafIssuerCN,
// distinct from the subject, so a verifying stunnel peer treats it as "issuer
// not found" (tolerated) rather than rejecting a self-signed leaf outright. The
// key still does its own signing; only the stamped issuer name differs.
//
// Both the on-wire carrier cert (identityCert) and the exported --pem cert
// (writeCertPEM) use this same form. That matters for --pem: a self-signed leaf
// is rejected by a bktunnel *server* backed by stunnel ("self-signed
// certificate"), so an exported cert must carry the distinct issuer to
// authenticate against every bktunnel server — Go, bash/stunnel, and Python
// alike — not just the Go one (whose pin check ignores the issuer). Standalone
// clients (curl, openssl s_client) present the cert regardless of its issuer, so
// the distinct-issuer form costs them nothing.
func certDER(priv crypto.Signer) ([]byte, error) {
	pub := priv.Public()
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(spki)
	cn := hex.EncodeToString(sum[:])[:40]

	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(certDays * 24 * time.Hour),
	}
	// parent supplies only the issuer name; priv (our key) does the signing.
	issuer := &x509.Certificate{Subject: pkix.Name{CommonName: leafIssuerCN}}
	return x509.CreateCertificate(rand.Reader, leaf, issuer, pub, priv)
}

// ---- pinning ----

// pinVerifier accepts the peer only if its leaf's public key matches one of the
// pinned bare public keys. Ed25519 and P-256 pins may be mixed freely — the
// comparison is on the bare wire bytes, which differ in length by type.
func pinVerifier(pins [][]byte) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("peer presented no certificate")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("parse peer cert: %w", err)
		}
		peer, err := barePub(leaf.PublicKey)
		if err != nil {
			return err
		}
		for _, pin := range pins {
			if subtle.ConstantTimeCompare(peer, pin) == 1 {
				return nil
			}
		}
		return errors.New("peer public key does not match any pin")
	}
}

func tlsConfig(cert tls.Certificate, pins [][]byte, isClient bool) *tls.Config {
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert}, // used on the server side
		// TLS 1.2 floor (not 1.3) so we interoperate with the bash/stunnel side
		// across stunnel/OpenSSL versions; Ed25519 auth works in both.
		MinVersion:            tls.VersionTLS12,
		InsecureSkipVerify:    true, // disable CA/hostname checks; we pin instead
		VerifyPeerCertificate: pinVerifier(pins),
	}
	if isClient {
		// Always present our client cert, whatever CA names the server
		// advertises. stunnel (as server) sends its pin subjects as the
		// acceptable client-CA list; Go's default selection from Certificates
		// byte-compares our cert's issuer DN against that list and, finding no
		// match, sends NO certificate — breaking mutual auth. GetClientCertificate
		// skips that filtering and hands over our cert unconditionally.
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &cert, nil
		}
	} else {
		cfg.ClientAuth = tls.RequireAnyClientCert // force mutual auth; the pin does the trusting
	}
	return cfg
}

// ---- forwarding ----

func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if hc, ok := dst.(interface{ CloseWrite() error }); ok {
			hc.CloseWrite() // half-close so the peer sees EOF
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
	a.Close()
	b.Close()
}

// runClient: plaintext in on accept, TLS out to the remote peer on connect.
func runClient(accept, connect string, cfg *tls.Config) error {
	ln, err := net.Listen("tcp", accept)
	if err != nil {
		return err
	}
	log.Printf("client: plaintext %s -> TLS %s", accept, connect)
	for {
		in, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err // listener closed: clean shutdown
			}
			log.Printf("accept: %v", err) // transient (e.g. fd exhaustion): keep serving
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go func() {
			out, err := tls.Dial("tcp", connect, cfg)
			if err != nil {
				log.Printf("dial %s: %v", connect, err)
				in.Close()
				return
			}
			pipe(in, out)
		}()
	}
}

// runServer: TLS in from the peer on accept, plaintext out to the local
// service on connect. The handshake (and pin check) completes on first I/O.
func runServer(accept, connect string, cfg *tls.Config) error {
	ln, err := tls.Listen("tcp", accept, cfg)
	if err != nil {
		return err
	}
	log.Printf("server: TLS %s -> plaintext %s", accept, connect)
	for {
		in, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err // listener closed: clean shutdown
			}
			log.Printf("accept: %v", err) // transient (e.g. fd exhaustion): keep serving
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go func() {
			out, err := net.Dial("tcp", connect)
			if err != nil {
				log.Printf("dial %s: %v", connect, err)
				in.Close()
				return
			}
			pipe(in, out)
		}()
	}
}

// ---- CLI ----

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// isTTY reports whether f is a terminal. It issues the terminal-attributes
// ioctl that isatty(3) uses (TCGETS on Linux, TIOCGETA on macOS) — which, unlike
// an os.ModeCharDevice check, correctly rejects non-tty character devices such
// as /dev/null. Done by hand to keep the binary free of golang.org/x/term.
func isTTY(f *os.File) bool {
	var termios [128]byte // opaque; >= sizeof(struct termios) on every target
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), ioctlGetTermios, uintptr(unsafe.Pointer(&termios[0])))
	return errno == 0
}

// bkDir returns ~/.bktunnel, the ssh-style default key directory.
func bkDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", errors.New("cannot determine home directory for ~/.bktunnel")
	}
	return filepath.Join(home, ".bktunnel"), nil
}

// genPromptSentinel is the placeholder flag parsing sees for a bare `-g` (no
// destination). The NUL prefix keeps it from colliding with a real path.
const genPromptSentinel = "\x00bktunnel-prompt-default"

// allowBareG lets `-g` take an OPTIONAL argument, which Go's flag package can't
// express. A `-g` token that is last, or followed by another option (but not a
// lone "-", which means stdout), gets the sentinel inserted after it so flag
// parsing still sees a value.
func allowBareG(args []string) []string {
	out := make([]string, 0, len(args)+1)
	for i, a := range args {
		out = append(out, a)
		if a == "-g" || a == "--g" {
			if i+1 >= len(args) || (strings.HasPrefix(args[i+1], "-") && args[i+1] != "-") {
				out = append(out, genPromptSentinel)
			}
		}
	}
	return out
}

// genToStdout prints the keypair like `-g -`: labelled lines to a terminal, or
// just the bare private key when piped/redirected (machine use). For a non-default
// algorithm the machine form carries an algo label so it round-trips through -k;
// Ed25519 stays a bare line for backward compatibility.
func genToStdout(algo, seedB64, pubB64 string) {
	switch {
	case isTTY(os.Stdout):
		fmt.Printf("privkey %s %s\npubkey  %s %s\n", algo, seedB64, algo, pubB64)
	case algo == algoEd25519:
		fmt.Println(seedB64)
	default:
		fmt.Printf("%s %s\n", algo, seedB64)
	}
}

// warnPEMToStdout notes that --pem has no effect when the key goes to stdout:
// the PEM cert/key are written next to a destination file, and there is no file
// when generating to stdout.
func warnPEMToStdout(pemOut bool) {
	if pemOut {
		log.Println("warning: --pem ignored when generating to stdout (needs a file destination)")
	}
}

// stdinReader is a single shared reader over os.Stdin so consecutive prompts
// don't lose input to a per-call bufio.Reader that buffered past its line.
var stdinReader = bufio.NewReader(os.Stdin)

// promptPath asks for a file path (ssh-keygen style): it returns def on empty
// input and expands a leading ~ to the home directory.
func promptPath(prompt, def string) string {
	fmt.Fprint(os.Stderr, prompt)
	line, _ := stdinReader.ReadString('\n')
	p := strings.TrimSpace(line)
	if p == "" {
		return def
	}
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			p = home + p[1:]
		}
	}
	return p
}

// promptYesNo writes prompt to stderr and returns def on empty input.
func promptYesNo(prompt string, def bool) bool {
	fmt.Fprint(os.Stderr, prompt)
	line, _ := stdinReader.ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "":
		return def
	case "y", "yes":
		return true
	default:
		return false
	}
}

// confirmOverwrite returns nil if path may be written: it's absent, or the user
// agrees. It refuses (never clobbers) when non-interactive.
func confirmOverwrite(path string) error {
	if _, err := os.Stat(path); err != nil {
		return nil // absent -> fine
	}
	if !isTTY(os.Stdin) {
		return fmt.Errorf("%s already exists (refusing to overwrite non-interactively)", path)
	}
	if !promptYesNo(fmt.Sprintf("%s already exists. Overwrite? [y/N] ", path), false) {
		return fmt.Errorf("declined overwrite of %s", path)
	}
	return nil
}

// writeKeypair writes the private key to file (0600, "<b64> # privkey") and the
// public key to file+".pub" (0644, "<b64> # pubkey"), ssh-keygen style, and
// echoes the shareable pubkey to stdout. When emitCert is set it also writes a
// PEM cert/key pair (see writeCertPEM). It prompts before overwriting the
// private key; that one yes covers the .pub, .crt and .key too (all are
// derivable from the private key, not separate secrets).
func writeKeypair(file string, priv crypto.Signer, algo, seedB64, pubB64 string, emitCert bool) error {
	pubFile := file + ".pub"
	if err := confirmOverwrite(file); err != nil {
		return err
	}
	// Remove any existing target first so the key is CREATED fresh: os.WriteFile
	// only applies the mode when it creates the file, so overwriting an existing
	// one would keep its old (possibly looser) mode. No chmod needed — unlike a
	// shell 0666 redirect, WriteFile's explicit mode is never loosened by umask
	// (umask only clears bits, and 0600/0644 have none it would add), so the
	// secret is never in a loose-mode file.
	_ = os.Remove(file)
	_ = os.Remove(pubFile)
	if err := os.WriteFile(file, []byte(seedB64+" # privkey "+algo+"\n"), 0o600); err != nil {
		return err
	}
	// ssh-style public line: "<type> <base64>", so the .pub pastes straight into
	// a peer's authorized_keys.
	if err := os.WriteFile(pubFile, []byte(algo+" "+pubB64+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "private key written to %s\n", file)
	fmt.Fprintf(os.Stderr, "public key  written to %s\n", pubFile)
	if emitCert {
		if err := writeCertPEM(file+".crt", file+".key", priv); err != nil {
			return err
		}
	}
	fmt.Printf("%s %s\n", algo, pubB64) // shareable pubkey to stdout (paste into authorized_keys)
	return nil
}

// writeCertPEM writes a PEM certificate to certFile (0644) and its PKCS#8
// private key to keyFile (0600). Together they let an OpenSSL-family client
// (curl --cert/--key, openssl s_client, most language TLS stacks) connect
// straight to a bktunnel server without running the bktunnel proxy: the server
// pins the bare public key, which is identical to the base64 key files, so these
// authenticate the same identity. The cert uses the same distinct-issuer form as
// the on-wire cert (see certDER) so it is accepted by every bktunnel server, not
// just the Go one. The caller has already confirmed any overwrite of the private
// key (these files are derived from it), so this does not prompt.
func writeCertPEM(certFile, keyFile string, priv crypto.Signer) error {
	der, err := certDER(priv)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	// Same create-fresh discipline as writeKeypair: remove then WriteFile so the
	// mode is applied to a new file rather than inherited from an old one. The key
	// carries the secret, so it is 0600; the cert is public, so 0644.
	_ = os.Remove(certFile)
	_ = os.Remove(keyFile)
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "certificate written to %s\n", certFile)
	fmt.Fprintf(os.Stderr, "cert key    written to %s\n", keyFile)
	return nil
}

// resolvePriv returns this host's algorithm and base64 private key from exactly
// one source: literal, "-"/"@-" (stdin), "@file", or the TUNNEL_PRIVKEY
// environment var (else the default id_ed25519 file). The "ed25519"/"p256" label
// that -g writes is parsed out; when absent the algorithm defaults to Ed25519,
// so a plain base64 key (or a pre-existing id_ed25519 file) still works.
func resolvePriv(arg string) (algo, b64 string, err error) {
	var raw string
	switch {
	case arg == "-" || arg == "@-":
		if isTTY(os.Stdin) {
			fmt.Fprint(os.Stderr, "Paste private key (base64), then press Enter: ")
		}
		line, _ := stdinReader.ReadString('\n')
		raw = line
	case strings.HasPrefix(arg, "@"):
		b, e := os.ReadFile(arg[1:])
		if e != nil {
			return "", "", e
		}
		raw = firstLine(string(b))
	case arg != "":
		raw = arg
	default:
		// no -k: prefer a default identity file (either key type), then $TUNNEL_PRIVKEY.
		if dir, e := bkDir(); e == nil {
			for _, name := range defaultKeyNames {
				if b, e := os.ReadFile(filepath.Join(dir, name)); e == nil {
					a, k := parsePriv(firstLine(string(b)))
					return a, k, nil
				}
			}
		}
		if s := os.Getenv("TUNNEL_PRIVKEY"); s != "" {
			a, k := parsePriv(s)
			return a, k, nil
		}
		return "", "", errors.New("no private key provided")
	}
	a, k := parsePriv(raw)
	return a, k, nil
}

// parsePriv splits a private-key line into (algorithm, base64 key). It honours
// the "ed25519"/"p256" token from a trailing "# privkey <algo>" comment (as -g
// writes) or a leading "[privkey] <algo> <b64>" label, drops the comment and any
// "privkey" word, and defaults to Ed25519 when no algorithm is present (so a
// bare base64 key — including a pre-existing id_ed25519 — is read as Ed25519).
func parsePriv(s string) (algo, b64 string) {
	algo = algoEd25519
	if i := strings.IndexByte(s, '#'); i >= 0 {
		for _, w := range strings.Fields(s[i+1:]) {
			if w == algoEd25519 || w == algoP256 {
				algo = w
			}
		}
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if rest, ok := strings.CutPrefix(s, "privkey"); ok && len(rest) > 0 && (rest[0] == ' ' || rest[0] == '\t') {
		s = strings.TrimSpace(rest)
	}
	for _, a := range []string{algoEd25519, algoP256} {
		if rest, ok := strings.CutPrefix(s, a); ok && len(rest) > 0 && (rest[0] == ' ' || rest[0] == '\t') {
			algo = a
			s = strings.TrimSpace(rest)
			break
		}
	}
	return algo, s
}

// loadPins expands -p specs (literals and @file lists) into pinned public keys.
// In @file lists, blank lines and '#' comments (whole-line or trailing) are ignored.
func loadPins(specs []string) ([][]byte, error) {
	var out [][]byte
	add := func(line string) error {
		b64 := pinKeyField(line)
		if b64 == "" {
			return nil // blank or comment-only line
		}
		pk, err := decodePub(b64)
		if err != nil {
			return err
		}
		out = append(out, pk)
		return nil
	}
	for _, s := range specs {
		if strings.HasPrefix(s, "@") {
			b, err := os.ReadFile(s[1:])
			if err != nil {
				return nil, err
			}
			for _, ln := range strings.Split(string(b), "\n") {
				if err := add(ln); err != nil {
					return nil, err
				}
			}
			continue
		}
		if err := add(s); err != nil {
			return nil, err
		}
	}
	if len(out) == 0 {
		return nil, errors.New("at least one -p (peer pub) is required")
	}
	return out, nil
}

// pinKeyField extracts the base64 public key from an ssh-style authorized_keys
// line, "[<type>] <base64> [comment]": a '#' starts a comment (whole-line or
// trailing), the remainder is whitespace-split, an optional leading type token
// (ed25519/p256) is skipped, the next field is the key, and any further text is
// a free-form comment. Returns "" for a blank or comment-only line.
func pinKeyField(line string) string {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = line[:i]
	}
	f := strings.Fields(line)
	if len(f) == 0 {
		return ""
	}
	if f[0] == algoEd25519 || f[0] == algoP256 {
		if len(f) < 2 {
			return ""
		}
		return f[1]
	}
	return f[0]
}

func main() {
	log.SetFlags(0)
	role := flag.String("r", "", "role: client|server")
	accept := flag.String("a", "", "accept address:port")
	connect := flag.String("c", "", "connect address:port")
	privArg := flag.String("k", "", "private key: literal | - | @file (else ~/.bktunnel/id_ed25519, then $TUNNEL_PRIVKEY)")
	genOut := flag.String("g", "", "generate keypair: -g FILE writes FILE + FILE.pub; -g - stdout; bare -g prompts for a path (default ~/.bktunnel/id_ed25519)")
	keyType := flag.String("t", algoEd25519, "key type for -g: ed25519 | p256 (P-256 is for browser/mobile clients that can't use Ed25519)")
	pemOut := flag.Bool("pem", false, "with -g to a file: also write FILE.crt (PEM cert) + FILE.key (PKCS#8 key) so curl/openssl-family clients can connect without the bktunnel proxy")
	pubOnly := flag.Bool("P", false, "print this host's pubkey (from -k / default key / $TUNNEL_PRIVKEY), then exit")
	showV := flag.Bool("v", false, "print version and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	var pubs multiFlag
	flag.Var(&pubs, "p", "peer pubkey (base64) or @file; repeatable (else ~/.bktunnel/authorized_keys)")
	flag.CommandLine.Parse(allowBareG(os.Args[1:]))

	if *showV || *showVersion || (flag.NArg() > 0 && flag.Arg(0) == "version") {
		printVersion()
		return
	}

	// no -p: fall back to ~/.bktunnel/authorized_keys (parsed like -p @file).
	if len(pubs) == 0 {
		if dir, err := bkDir(); err == nil {
			authFile := filepath.Join(dir, "authorized_keys")
			if _, err := os.Stat(authFile); err == nil {
				pubs = append(pubs, "@"+authFile)
			}
		}
	}

	var privStr, privAlgo string

	if *genOut != "" {
		algo := *keyType
		priv, err := generateKey(algo)
		fatalUsage(err)
		_, seed, err := privSeed(priv)
		fatal(err)
		seedB64 := base64.StdEncoding.EncodeToString(seed)
		pubBare, err := barePub(priv.Public())
		fatal(err)
		pubB64 := base64.StdEncoding.EncodeToString(pubBare)
		switch {
		case *genOut == genPromptSentinel:
			// -g with no destination
			if isTTY(os.Stdin) {
				dir, err := bkDir()
				fatal(err)
				idFile := filepath.Join(dir, defaultKeyName(algo))
				// ssh-keygen style: ask where to save, defaulting to idFile.
				path := promptPath(fmt.Sprintf("Enter file in which to save the key (%s): ", idFile), idFile)
				pdir := filepath.Dir(path)
				fatal(os.MkdirAll(pdir, 0o700))
				if pdir == dir {
					_ = os.Chmod(dir, 0o700) // tighten our own default dir if it pre-existed loose
				}
				fatal(writeKeypair(path, priv, algo, seedB64, pubB64, *pemOut))
			} else {
				warnPEMToStdout(*pemOut)
				genToStdout(algo, seedB64, pubB64) // non-interactive: behave as -g -
			}
		case *genOut == "-":
			warnPEMToStdout(*pemOut)
			genToStdout(algo, seedB64, pubB64)
		default:
			fatal(writeKeypair(*genOut, priv, algo, seedB64, pubB64, *pemOut))
		}
		if *privArg != "" {
			log.Println("warning: -k ignored; using the freshly generated private key")
		}
		privStr, privAlgo = seedB64, algo
		// run only if the remaining required tunnel opts are present
		if *role == "" || *accept == "" || *connect == "" || len(pubs) == 0 {
			return
		}
	} else {
		var err error
		privAlgo, privStr, err = resolvePriv(*privArg)
		fatalUsage(err)
	}

	priv, err := decodePriv(privAlgo, privStr)
	fatal(err)
	if *pubOnly {
		// derive the public key from the private key and print the ssh-style
		// "<type> <base64>" line (paste into a peer's authorized_keys).
		pub, err := barePub(priv.Public())
		fatal(err)
		fmt.Printf("%s %s\n", privAlgo, base64.StdEncoding.EncodeToString(pub))
		return
	}
	if *accept == "" || *connect == "" {
		fatalUsage(errors.New("-a (accept) and -c (connect) are required"))
	}
	pins, err := loadPins(pubs)
	fatalUsage(err)
	cert, err := identityCert(priv)
	fatal(err)

	switch *role {
	case "client":
		fatal(runClient(*accept, *connect, tlsConfig(cert, pins, true)))
	case "server":
		fatal(runServer(*accept, *connect, tlsConfig(cert, pins, false)))
	default:
		fatalUsage(errors.New("-r must be 'client' or 'server'"))
	}
}

func fatal(err error) {
	if err != nil {
		log.Fatalf("error: %v", err)
	}
}

// fatalUsage prints err and exits 2 — the convention (matching the bash tool)
// for CLI usage/validation errors, distinct from fatal's exit 1 for runtime
// failures.
func fatalUsage(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
}
