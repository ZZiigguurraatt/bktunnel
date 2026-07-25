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

// TestExpandBareOptionalArgs covers the optional-argument rewrite for -g and
// --cert: a bare token (last, or followed by another option) gets its sentinel;
// -g -, -g FILE, --cert FILE, and unrelated flags are left untouched.
func TestExpandBareOptionalArgs(t *testing.T) {
	g := genPromptSentinel
	c := certDeriveSentinel
	cases := []struct {
		in, want []string
	}{
		{[]string{"-g"}, []string{"-g", g}},
		{[]string{"-g", "-"}, []string{"-g", "-"}},
		{[]string{"-g", "file"}, []string{"-g", "file"}},
		{[]string{"-g", "-r", "client"}, []string{"-g", g, "-r", "client"}},
		{[]string{"-r", "client", "-g"}, []string{"-r", "client", "-g", g}},
		{[]string{"-k", "x"}, []string{"-k", "x"}},
		{[]string{"--cert"}, []string{"--cert", c}},
		{[]string{"-cert"}, []string{"-cert", c}},
		{[]string{"--cert", "id.crt"}, []string{"--cert", "id.crt"}},
		{[]string{"--cert", "-r", "server"}, []string{"--cert", c, "-r", "server"}},
		{[]string{"-r", "server", "--cert"}, []string{"-r", "server", "--cert", c}},
	}
	for _, tc := range cases {
		got := expandBareOptionalArgs(tc.in)
		if len(got) != len(tc.want) {
			t.Errorf("expandBareOptionalArgs(%v) = %v, want %v", tc.in, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("expandBareOptionalArgs(%v) = %v, want %v", tc.in, got, tc.want)
				break
			}
		}
	}
}
