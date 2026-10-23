// Package match implements IAM wildcard matching for actions and resource
// ARNs, without regular expressions.
//
// Semantics (docs/research.md §2.6, edge cases E22–E26):
//
//   - '*' matches any sequence of characters (including none) and '?' matches
//     exactly one character (a Unicode code point, not a byte).
//   - Actions are case-insensitive ("IAM:putrolepolicy" matches
//     "iam:PutRolePolicy").
//   - ARNs are case-sensitive and matched segment by segment (segments are
//     separated by ':'). A '*' inside a segment does not cross a ':'; a
//     segment whose last character is '*' may expand over the following
//     colons, so "arn:aws:iam::*" matches every IAM ARN of every account and
//     "arn:aws:lambda:*:*:function:*" matches qualified function ARNs.
//
// Both matchers run in polynomial time, so hostile patterns such as
// "*:*:*:*:*" cannot cause exponential backtracking.
package match

import "strings"

// Glob reports whether s matches pattern, where '*' matches any sequence of
// characters and '?' one character. It is case-sensitive and treats ':' like
// any other character, as the StringLike condition operator does.
func Glob(pattern, s string) bool {
	if isASCII(pattern) && isASCII(s) {
		return globASCII(pattern, s, false)
	}
	return glob([]rune(pattern), []rune(s))
}

// Action reports whether an IAM action pattern matches an action name,
// ignoring case.
func Action(pattern, action string) bool {
	if isASCII(pattern) && isASCII(action) {
		return globASCII(pattern, action, true)
	}
	return glob([]rune(strings.ToLower(pattern)), []rune(strings.ToLower(action)))
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// globASCII is glob on bytes, without allocations; fold compares ASCII
// letters case-insensitively. Both strings must be ASCII so that '?' and
// bytes are the same as runes.
func globASCII(pattern, s string, fold bool) bool {
	p, i := 0, 0
	starP, starI := -1, 0
	for i < len(s) {
		switch {
		case p < len(pattern) && pattern[p] == '*':
			starP, starI = p, i
			p++
		case p < len(pattern) && (pattern[p] == s[i] || pattern[p] == '?' || fold && lower(pattern[p]) == lower(s[i])):
			p++
			i++
		case starP >= 0:
			starI++
			i = starI
			p = starP + 1
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// glob matches s against pattern with '*' and '?'. It uses the classic
// two-pointer algorithm: on a mismatch it backtracks only to the most recent
// '*', which is enough for this pattern language and keeps the cost at
// O(len(pattern) * len(s)).
func glob(pattern, s []rune) bool {
	p, i := 0, 0
	starP, starI := -1, 0
	for i < len(s) {
		switch {
		case p < len(pattern) && pattern[p] == '*':
			starP, starI = p, i
			p++
		case p < len(pattern) && (pattern[p] == s[i] || pattern[p] == '?'):
			p++
			i++
		case starP >= 0:
			// Let the last '*' absorb one more character and retry.
			starI++
			i = starI
			p = starP + 1
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// ARN reports whether a resource pattern from a policy matches an ARN.
// The pattern "*" matches everything.
func ARN(pattern, arn string) bool {
	if pattern == "*" {
		return true
	}
	if isASCII(pattern) && isASCII(arn) {
		return arnASCII(pattern, arn)
	}
	segs := splitRunes(pattern)
	parts := splitRunes(arn)
	n := len(parts)

	// next[j] reports whether segs[i+1:] matches parts[j:]; cur is the row
	// for segs[i:]. Rows are filled from the last segment backwards, so the
	// cost is O(len(segs) * len(parts)) glob calls and O(len(parts)) memory.
	next := make([]bool, n+1)
	cur := make([]bool, n+1)
	next[n] = true
	for i := len(segs) - 1; i >= 0; i-- {
		seg := segs[i]
		expands := len(seg) > 0 && seg[len(seg)-1] == '*'
		cur[n] = false
		// tail is true when next[k] holds for some k > j: an expanding
		// segment starting at part j may end before any such k.
		tail := false
		for j := n - 1; j >= 0; j-- {
			tail = tail || next[j+1]
			if expands {
				// The segment's head must match inside parts[j]; its final
				// '*' then takes the rest of parts[j] and any number of the
				// following parts. Parts never contain ':', so glob on the
				// single part checks the head.
				cur[j] = tail && glob(seg, parts[j])
			} else {
				cur[j] = next[j+1] && glob(seg, parts[j])
			}
		}
		next, cur = cur, next
	}
	return next[0]
}

func splitRunes(s string) [][]rune {
	fields := strings.Split(s, ":")
	out := make([][]rune, len(fields))
	for i, f := range fields {
		out[i] = []rune(f)
	}
	return out
}

// arnASCII is ARN for ASCII inputs: the same dynamic program over segments,
// with byte globs and stack buffers for ARNs of up to 16 segments.
func arnASCII(pattern, arn string) bool {
	var segBuf, partBuf [16]string
	segs := splitColon(pattern, segBuf[:0])
	parts := splitColon(arn, partBuf[:0])
	n := len(parts)
	var bufA, bufB [17]bool
	var next, cur []bool
	if n+1 <= len(bufA) {
		next, cur = bufA[:n+1], bufB[:n+1]
	} else {
		next, cur = make([]bool, n+1), make([]bool, n+1)
	}
	next[n] = true
	for i := len(segs) - 1; i >= 0; i-- {
		seg := segs[i]
		expands := len(seg) > 0 && seg[len(seg)-1] == '*'
		cur[n] = false
		tail := false
		for j := n - 1; j >= 0; j-- {
			tail = tail || next[j+1]
			if expands {
				cur[j] = tail && globASCII(seg, parts[j], false)
			} else {
				cur[j] = next[j+1] && globASCII(seg, parts[j], false)
			}
		}
		next, cur = cur, next
	}
	return next[0]
}

// splitColon is strings.Split(s, ":") into buf (no allocation while the
// ARN has at most len(buf) segments).
func splitColon(s string, buf []string) []string {
	for {
		i := strings.IndexByte(s, ':')
		if i < 0 {
			return append(buf, s)
		}
		buf = append(buf, s[:i])
		s = s[i+1:]
	}
}
