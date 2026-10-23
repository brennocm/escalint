package match

import (
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestAction(t *testing.T) {
	tests := []struct {
		pattern, action string
		want            bool
	}{
		{"*", "iam:PassRole", true},
		{"iam:*", "iam:PassRole", true},
		{"iam:*", "sts:AssumeRole", false},
		{"iam:PassRole", "iam:PassRole", true},
		// E23: action names are case-insensitive.
		{"IAM:passrole", "iam:PassRole", true},
		// E22: wildcard in the middle of an action name.
		{"iam:*Policy*", "iam:PutRolePolicy", true},
		{"iam:*Policy*", "iam:AttachUserPolicy", true},
		{"iam:*Policy*", "iam:PassRole", false},
		{"iam:Put*Policy", "iam:PutRolePolicy", true},
		{"iam:Put*Policy", "iam:PutRolePolicyX", false},
		{"iam:?assRole", "iam:PassRole", true},
		{"iam:?assRole", "iam:assRole", false},
		{"s3:Get*", "s3:GetObject", true},
		{"s3:Get*", "s3:PutObject", false},
		{"*:Get*", "ec2:GetConsoleOutput", true},
		{"", "", true},
		{"", "iam:PassRole", false},
		{"iam:PassRole", "iam:PassRol", false},
		{"**", "a", true},
	}
	for _, tc := range tests {
		if got := Action(tc.pattern, tc.action); got != tc.want {
			t.Errorf("Action(%q, %q) = %v, want %v", tc.pattern, tc.action, got, tc.want)
		}
	}
}

func TestGlob(t *testing.T) {
	tests := []struct {
		pattern, s string
		want       bool
	}{
		{"repo:example-org/*", "repo:example-org/app:ref:refs/heads/main", true},
		{"repo:example-org/*", "repo:Example-org/app", false}, // case-sensitive
		{"a?c", "abc", true},
		{"*", "", true},
	}
	for _, tc := range tests {
		if got := Glob(tc.pattern, tc.s); got != tc.want {
			t.Errorf("Glob(%q, %q) = %v, want %v", tc.pattern, tc.s, got, tc.want)
		}
	}
}

func TestARN(t *testing.T) {
	tests := []struct {
		pattern, arn string
		want         bool
	}{
		{"*", "arn:aws:iam::111111111111:role/x", true},
		{"arn:aws:iam::111111111111:role/x", "arn:aws:iam::111111111111:role/x", true},
		// E24: resource names are case-sensitive.
		{"arn:aws:iam::111111111111:user/Bob", "arn:aws:iam::111111111111:user/bob", false},
		{"arn:aws:iam::111111111111:role/*", "arn:aws:iam::111111111111:role/app/deploy", true},
		{"arn:aws:iam::111111111111:role/app-*", "arn:aws:iam::111111111111:role/web", false},
		// E25: '*' matches '/' and the example list from the Resource docs.
		{"arn:aws:s3:::amzn-s3-demo-bucket/*/test/*", "arn:aws:s3:::amzn-s3-demo-bucket/1/2/test/object.jpg", true},
		{"arn:aws:s3:::amzn-s3-demo-bucket/*/test/*", "arn:aws:s3:::amzn-s3-demo-bucket//test/object.jpg", true},
		{"arn:aws:s3:::amzn-s3-demo-bucket/*/test/*", "arn:aws:s3:::amzn-s3-demo-bucket/1/test/", true},
		{"arn:aws:s3:::amzn-s3-demo-bucket/*/test/*", "arn:aws:s3:::amzn-s3-demo-bucket/1-test/object.jpg", false},
		{"arn:aws:s3:::amzn-s3-demo-bucket/*/test/*", "arn:aws:s3:::amzn-s3-demo-bucket/test/object.jpg", false},
		{"arn:aws:s3:::amzn-s3-demo-bucket/*/test/*", "arn:aws:s3:::amzn-s3-demo-bucket/1/2/test.jpg", false},
		// E26: a trailing '*' in a segment expands across colons.
		{"arn:aws:iam::*", "arn:aws:iam::111111111111:role/x", true},
		{"arn:aws:lambda:*:111111111111:function:*", "arn:aws:lambda:us-east-1:111111111111:function:f:1", true},
		{"arn:aws:lambda:us-east-1:111111111111:function:f*", "arn:aws:lambda:us-east-1:111111111111:function:f:1", true},
		// A '*' that is not last in its segment does not cross ':'.
		{"arn:aws:lambda:us-east-1:111111111111:function:f*x", "arn:aws:lambda:us-east-1:111111111111:function:f:x", false},
		{"arn:aws:lambda:us-east-1:111111111111:function:f*x", "arn:aws:lambda:us-east-1:111111111111:function:fooox", true},
		{"arn:aws:iam::*:role/admin", "arn:aws:iam::111111111111:role/admin", true},
		{"arn:aws:iam::*:role/admin", "arn:aws:iam::111111111111:role/other", false},
		{"arn:aws:iam::????????????:role/x", "arn:aws:iam::111111111111:role/x", true},
		{"arn:aws:iam::???:role/x", "arn:aws:iam::111111111111:role/x", false},
		// '?' never matches ':'.
		{"arn:aws:iam:?:111111111111:role/x", "arn:aws:iam:::111111111111:role/x", false},
		{"arn:aws:s3:::bucket", "arn:aws:s3:::bucket/key", false},
		{"arn:aws:s3:::bucket*", "arn:aws:s3:::bucket/key", true},
		// '?' is one character, not one byte.
		{"arn:aws:s3:::bucket/caf?", "arn:aws:s3:::bucket/café", true},
		{"arn:aws:s3:::bucket/caf??", "arn:aws:s3:::bucket/café", false},
		{"", "", true},
		{"", "arn:aws:s3:::b", false},
		{"arn:aws:s3:::*", "arn:aws-cn:s3:::b", false},
	}
	for _, tc := range tests {
		if got := ARN(tc.pattern, tc.arn); got != tc.want {
			t.Errorf("ARN(%q, %q) = %v, want %v", tc.pattern, tc.arn, got, tc.want)
		}
	}
}

// actionOracle is an independent reference implementation built on regexp.
func actionOracle(pattern, action string) bool {
	var b strings.Builder
	b.WriteString("(?is)^")
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String()).MatchString(action)
}

// arnOracle restates the segment rules with regexps and plain recursion. It
// is exponential in the worst case, which is fine for short fuzz inputs.
func arnOracle(pattern, arn string) bool {
	if pattern == "*" {
		return true
	}
	return arnRec(strings.Split(pattern, ":"), strings.Split(arn, ":"))
}

func arnRec(segs, parts []string) bool {
	if len(segs) == 0 {
		return len(parts) == 0
	}
	if len(parts) == 0 {
		return false
	}
	seg := segs[0]
	if strings.HasSuffix(seg, "*") {
		re := regexp.MustCompile("(?s)^" + segRegexp(seg[:len(seg)-1]) + ".*$")
		for k := 1; k <= len(parts); k++ {
			joined := strings.Join(parts[:k], ":")
			// The head must sit inside the first part.
			if headFits(seg[:len(seg)-1], parts[0]) && re.MatchString(joined) && arnRec(segs[1:], parts[k:]) {
				return true
			}
		}
		return false
	}
	re := regexp.MustCompile("^" + segRegexp(seg) + "$")
	return re.MatchString(parts[0]) && arnRec(segs[1:], parts[1:])
}

func headFits(head, first string) bool {
	re := regexp.MustCompile("^" + segRegexp(head))
	return re.MatchString(first)
}

func segRegexp(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '*':
			b.WriteString("[^:]*")
		case '?':
			b.WriteString("[^:]")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	return b.String()
}

func TestOraclesAgreeOnTable(t *testing.T) {
	for _, c := range [][2]string{
		{"arn:aws:iam::*", "arn:aws:iam::111111111111:role/x"},
		{"a*:b", "ax:y:b"},
		{"a*b*", "aab:c"},
	} {
		if ARN(c[0], c[1]) != arnOracle(c[0], c[1]) {
			t.Errorf("ARN and oracle disagree on %q %q", c[0], c[1])
		}
	}
}

func FuzzMatchAction(f *testing.F) {
	f.Add("iam:*Policy*", "iam:PutRolePolicy")
	f.Add("?*?", "ab")
	f.Add("IAM:Pass*", "iam:passrole")
	f.Fuzz(func(t *testing.T, pattern, action string) {
		// Policy and snapshot strings come from JSON and are valid UTF-8.
		if len(pattern) > 64 || len(action) > 64 || !utf8.ValidString(pattern) || !utf8.ValidString(action) {
			return
		}
		if got, want := Action(pattern, action), actionOracle(pattern, action); got != want {
			t.Fatalf("Action(%q, %q) = %v, oracle says %v", pattern, action, got, want)
		}
		if !Action(action, action) && !strings.ContainsAny(action, "*?") {
			t.Fatalf("Action(%q, %q) must match itself", action, action)
		}
	})
}

func FuzzMatchARN(f *testing.F) {
	f.Add("arn:aws:iam::*", "arn:aws:iam::111111111111:role/x")
	f.Add("a*:?:b*", "abc:d:bb:c")
	f.Add("*:*:*", "a:b:c:d")
	f.Fuzz(func(t *testing.T, pattern, arn string) {
		if len(pattern) > 32 || len(arn) > 32 || strings.Count(pattern, ":") > 8 || strings.Count(arn, ":") > 8 ||
			!utf8.ValidString(pattern) || !utf8.ValidString(arn) {
			return
		}
		if got, want := ARN(pattern, arn), arnOracle(pattern, arn); got != want {
			t.Fatalf("ARN(%q, %q) = %v, oracle says %v", pattern, arn, got, want)
		}
		if !strings.ContainsAny(arn, "*?") && !ARN(arn, arn) {
			t.Fatalf("ARN(%q) must match itself", arn)
		}
	})
}

func BenchmarkAction(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Action("iam:*Policy*", "iam:AttachRolePolicy")
	}
}

func BenchmarkARN(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ARN("arn:aws:lambda:*:111111111111:function:*", "arn:aws:lambda:us-east-1:111111111111:function:f:1")
	}
}

// BenchmarkARNHostile shows the cost stays polynomial for adversarial input.
func BenchmarkARNHostile(b *testing.B) {
	pattern := strings.Repeat("*:", 40) + "x"
	arn := strings.Repeat("a:", 80) + "y"
	for i := 0; i < b.N; i++ {
		ARN(pattern, arn)
	}
}
