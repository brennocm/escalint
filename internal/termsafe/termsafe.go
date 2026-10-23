// Package termsafe makes untrusted text safe to print on a terminal.
//
// Names, tags, ARNs and policy keys in a snapshot are controlled by whoever
// can change the account. Printed raw, they could carry ANSI escape
// sequences (clear the screen, rewrite earlier lines), newlines that forge
// output lines, or bidirectional overrides that disguise text. Every piece of
// snapshot-derived text written to a terminal goes through Line.
package termsafe

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Line returns s with every control character, Unicode format character
// (bidirectional overrides, zero-width characters) and invalid UTF-8 byte
// replaced by a visible escape such as \x1b or \u202e. Newlines and tabs are
// escaped too: one value must stay on one line.
func Line(s string) string {
	if safe(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size <= 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r < 0x80 && (unicode.IsControl(r) || r == '\\'):
			if r == '\\' {
				b.WriteString(`\\`)
			} else {
				fmt.Fprintf(&b, `\x%02x`, r)
			}
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

// safe is the fast path: printable ASCII without backslashes.
func safe(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c >= 0x7f || c == '\\' {
			return false
		}
	}
	return true
}
