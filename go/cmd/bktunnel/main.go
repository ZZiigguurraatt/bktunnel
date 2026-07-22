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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
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

// ---- key material (base64 of raw 32 bytes, same key format as the bash tool) ----

func decodePriv(b64 string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, fmt.Errorf("private key: %w", err)
	}
	if len(raw) != ed25519.SeedSize {
		return nil, fmt.Errorf("private key must be %d bytes, got %d", ed25519.SeedSize, len(raw))
	}
	return ed25519.NewKeyFromSeed(raw), nil
}

func decodePub(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, fmt.Errorf("pubkey: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("pubkey must be %d bytes, got %d", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// identityCert mints an in-memory carrier cert over the identity key. Nothing is
// written to disk. Its CN is sha256(SPKI)[:40] — the same key-hash scheme the
// bash tool pins on. Crucially it is NOT self-signed: the issuer name is
// leafIssuerCN, distinct from the subject, so a verifying stunnel peer treats it
// as "issuer not found" (tolerated) and pins us by public key, rather than
// rejecting a self-signed leaf outright. We still sign with our own key; only
// the issuer NAME differs from the subject (a self-signed cert sets them equal).
func identityCert(priv ed25519.PrivateKey) (tls.Certificate, error) {
	pub := priv.Public().(ed25519.PublicKey)
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return tls.Certificate{}, err
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
	der, err := x509.CreateCertificate(rand.Reader, leaf, issuer, pub, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}

// ---- pinning ----

// pinVerifier accepts the peer only if its leaf carries one of the pinned keys.
func pinVerifier(pins []ed25519.PublicKey) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("peer presented no certificate")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("parse peer cert: %w", err)
		}
		peer, ok := leaf.PublicKey.(ed25519.PublicKey)
		if !ok {
			return errors.New("peer key is not Ed25519")
		}
		for _, pin := range pins {
			if subtle.ConstantTimeCompare(peer, pin) == 1 {
				return nil
			}
		}
		return errors.New("peer public key does not match any pin")
	}
}

func tlsConfig(cert tls.Certificate, pins []ed25519.PublicKey, isClient bool) *tls.Config {
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
// just the bare private key when piped/redirected (machine use).
func genToStdout(seedB64, pubB64 string) {
	if isTTY(os.Stdout) {
		fmt.Printf("privkey %s\npubkey  %s\n", seedB64, pubB64)
	} else {
		fmt.Println(seedB64)
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
// echoes the shareable pubkey to stdout. It prompts before overwriting the
// private key; that one yes covers the .pub too (it is derivable, not a
// separate secret).
func writeKeypair(file, seedB64, pubB64 string) error {
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
	if err := os.WriteFile(file, []byte(seedB64+" # privkey\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(pubFile, []byte(pubB64+" # pubkey\n"), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "private key written to %s\n", file)
	fmt.Fprintf(os.Stderr, "public key  written to %s\n", pubFile)
	fmt.Printf("pubkey %s\n", pubB64) // shareable pubkey to stdout
	return nil
}

// resolvePriv returns this host's base64 private key from exactly one source:
// literal, "-"/"@-" (stdin), "@file", or the TUNNEL_PRIVKEY environment var.
// A leading "privkey" label (as written by -g) is accepted and stripped, so a
// file produced by `-g FILE` round-trips through -k @FILE.
func resolvePriv(arg string) (string, error) {
	var raw string
	switch {
	case arg == "-" || arg == "@-":
		if isTTY(os.Stdin) {
			fmt.Fprint(os.Stderr, "Paste private key (base64), then press Enter: ")
		}
		line, _ := stdinReader.ReadString('\n')
		raw = line
	case strings.HasPrefix(arg, "@"):
		b, err := os.ReadFile(arg[1:])
		if err != nil {
			return "", err
		}
		raw = firstLine(string(b))
	case arg != "":
		raw = arg
	default:
		// no -k: prefer the default identity file, then $TUNNEL_PRIVKEY.
		if dir, err := bkDir(); err == nil {
			if b, err := os.ReadFile(filepath.Join(dir, "id_ed25519")); err == nil {
				return stripPrivLabel(firstLine(string(b))), nil
			}
		}
		if s := os.Getenv("TUNNEL_PRIVKEY"); s != "" {
			return stripPrivLabel(s), nil
		}
		return "", errors.New("no private key provided")
	}
	return stripPrivLabel(raw), nil
}

// stripPrivLabel drops a trailing "# ..." comment (e.g. the "# privkey"
// annotation on ~/.bktunnel/id_ed25519; base64 has no '#'), trims whitespace,
// then drops an optional leading "privkey" label (only when followed by
// whitespace, so a bare base64 key starting with those letters is left intact).
func stripPrivLabel(s string) string {
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if rest, ok := strings.CutPrefix(s, "privkey"); ok && len(rest) > 0 && (rest[0] == ' ' || rest[0] == '\t') {
		s = strings.TrimSpace(rest)
	}
	return s
}

// loadPins expands -p specs (literals and @file lists) into pinned public keys.
// In @file lists, blank lines and '#' comments (whole-line or trailing) are ignored.
func loadPins(specs []string) ([]ed25519.PublicKey, error) {
	var out []ed25519.PublicKey
	add := func(b64 string) error {
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
				if i := strings.IndexByte(ln, '#'); i >= 0 {
					ln = ln[:i]
				}
				if ln = strings.TrimSpace(ln); ln == "" {
					continue
				}
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

func main() {
	log.SetFlags(0)
	role := flag.String("r", "", "role: client|server")
	accept := flag.String("a", "", "accept address:port")
	connect := flag.String("c", "", "connect address:port")
	privArg := flag.String("k", "", "private key: literal | - | @file (else ~/.bktunnel/id_ed25519, then $TUNNEL_PRIVKEY)")
	genOut := flag.String("g", "", "generate keypair: -g FILE writes FILE + FILE.pub; -g - stdout; bare -g prompts for a path (default ~/.bktunnel/id_ed25519)")
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

	var privStr string

	if *genOut != "" {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		fatal(err)
		seedB64 := base64.StdEncoding.EncodeToString(priv.Seed())
		pubB64 := base64.StdEncoding.EncodeToString(pub)
		switch {
		case *genOut == genPromptSentinel:
			// -g with no destination
			if isTTY(os.Stdin) {
				dir, err := bkDir()
				fatal(err)
				idFile := filepath.Join(dir, "id_ed25519")
				// ssh-keygen style: ask where to save, defaulting to idFile.
				path := promptPath(fmt.Sprintf("Enter file in which to save the key (%s): ", idFile), idFile)
				pdir := filepath.Dir(path)
				fatal(os.MkdirAll(pdir, 0o700))
				if pdir == dir {
					_ = os.Chmod(dir, 0o700) // tighten our own default dir if it pre-existed loose
				}
				fatal(writeKeypair(path, seedB64, pubB64))
			} else {
				genToStdout(seedB64, pubB64) // non-interactive: behave as -g -
			}
		case *genOut == "-":
			genToStdout(seedB64, pubB64)
		default:
			fatal(writeKeypair(*genOut, seedB64, pubB64))
		}
		if *privArg != "" {
			log.Println("warning: -k ignored; using the freshly generated private key")
		}
		privStr = seedB64
		// run only if the remaining required tunnel opts are present
		if *role == "" || *accept == "" || *connect == "" || len(pubs) == 0 {
			return
		}
	} else {
		var err error
		privStr, err = resolvePriv(*privArg)
		fatalUsage(err)
	}

	priv, err := decodePriv(privStr)
	fatal(err)
	if *pubOnly {
		// Ed25519's public key derives from the seed; recover it from -k.
		pub := priv.Public().(ed25519.PublicKey)
		fmt.Printf("pubkey %s\n", base64.StdEncoding.EncodeToString(pub))
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
