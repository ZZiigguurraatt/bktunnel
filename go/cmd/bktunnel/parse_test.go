package main

import "testing"

// TestStripPrivLabel covers the private-key normalizer: it drops a trailing
// "# ..." comment (the "# privkey" annotation on ~/.bktunnel/id_ed25519), trims,
// and strips a leading "privkey" label — but leaves a bare key intact.
func TestStripPrivLabel(t *testing.T) {
	cases := map[string]string{
		"ABC=":             "ABC=",
		"  ABC=  ":         "ABC=",
		"privkey ABC=":     "ABC=",
		"ABC= # privkey":   "ABC=",
		"privkey ABC= # x": "ABC=",
		"ABC=\n":           "ABC=",
		"privkeyABC=":      "privkeyABC=", // no space after "privkey" -> not a label
		"# whole comment":  "",
	}
	for in, want := range cases {
		if got := stripPrivLabel(in); got != want {
			t.Errorf("stripPrivLabel(%q) = %q, want %q", in, got, want)
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
