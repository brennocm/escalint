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
	return glob([]rune(pattern), []rune(s))
}

// Action reports whether an IAM action pattern matches an action name.
func Action(pattern, action string) bool {
	return glob([]rune(strings.ToLower(pattern)), []rune(strings.ToLower(action)))
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
