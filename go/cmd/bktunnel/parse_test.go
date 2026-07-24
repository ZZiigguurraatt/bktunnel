package main

import "testing"

// TestParsePriv covers the private-key parser: it splits (algorithm, base64
// key), honouring an "ed25519"/"p256" token from a "# privkey <algo>" comment or
// a leading label, dropping the comment and any "privkey" word, and defaulting
// to Ed25519 when no algorithm is present (a bare key is left intact).
func TestParsePriv(t *testing.T) {
	cases := []struct {
		in         string
		algo, want string
	}{
		{"ABC=", algoEd25519, "ABC="},
		{"  ABC=  ", algoEd25519, "ABC="},
		{"privkey ABC=", algoEd25519, "ABC="},
		{"ABC= # privkey", algoEd25519, "ABC="},
		{"privkey ABC= # x", algoEd25519, "ABC="},
		{"ABC=\n", algoEd25519, "ABC="},
		{"privkeyABC=", algoEd25519, "privkeyABC="}, // no space after "privkey" -> not a label
		{"# whole comment", algoEd25519, ""},
		// algorithm detection
		{"ABC= # privkey p256", algoP256, "ABC="},
		{"ABC= # privkey ed25519", algoEd25519, "ABC="},
		{"privkey p256 ABC=", algoP256, "ABC="},
		{"p256 ABC=", algoP256, "ABC="},
		{"ed25519 ABC=", algoEd25519, "ABC="},
	}
	for _, c := range cases {
		algo, got := parsePriv(c.in)
		if algo != c.algo || got != c.want {
			t.Errorf("parsePriv(%q) = (%q, %q), want (%q, %q)", c.in, algo, got, c.algo, c.want)
		}
	}
}

// TestAllowBareG covers the optional-argument rewrite for -g: a bare -g (last,
// or followed by another option) gets the sentinel; -g -, -g FILE, and
// unrelated flags are left untouched.
func TestAllowBareG(t *testing.T) {
	s := genPromptSentinel
	cases := []struct {
		in, want []string
	}{
		{[]string{"-g"}, []string{"-g", s}},
		{[]string{"-g", "-"}, []string{"-g", "-"}},
		{[]string{"-g", "file"}, []string{"-g", "file"}},
		{[]string{"-g", "-r", "client"}, []string{"-g", s, "-r", "client"}},
		{[]string{"-r", "client", "-g"}, []string{"-r", "client", "-g", s}},
		{[]string{"-k", "x"}, []string{"-k", "x"}},
	}
	for _, c := range cases {
		got := allowBareG(c.in)
		if len(got) != len(c.want) {
			t.Errorf("allowBareG(%v) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("allowBareG(%v) = %v, want %v", c.in, got, c.want)
				break
			}
		}
	}
}
