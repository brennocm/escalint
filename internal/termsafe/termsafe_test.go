package termsafe

import (
	"strings"
	"testing"
	"unicode"
)

func TestLine(t *testing.T) {
	tests := []struct{ in, want string }{
		{"plain arn:aws:iam::111111111111:role/x", "plain arn:aws:iam::111111111111:role/x"},
		{"café ✓", "café ✓"},
		{"\x1b[2Jcleared", `\x1b[2Jcleared`},
		{"line1\nescalint: no findings", `line1\x0aescalint: no findings`},
		{"tab\there", `tab\x09here`},
		{"evil\u202egnp.exe", "evil\\u202egnp.exe"},
		{"zero\u200bwidth", "zero\\u200bwidth"},
		{"c1\u009bcontrol", `c1\u009bcontrol`},
		{"bad\xffutf8", `bad\xffutf8`},
		{`back\slash`, `back\\slash`},
		{"del\x7f", `del\x7f`},
		{"", ""},
	}
	for _, tc := range tests {
		if got := Line(tc.in); got != tc.want {
			t.Errorf("Line(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func FuzzLine(f *testing.F) {
	f.Add("\x1b]0;title\x07")
	f.Add("ok")
	f.Fuzz(func(t *testing.T, s string) {
		out := Line(s)
		for _, r := range out {
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '�' && !strings.Contains(s, "�") {
				t.Fatalf("Line(%q) = %q still contains %U", s, out, r)
			}
		}
	})
}
