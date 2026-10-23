package arn

import "testing"

func TestParse(t *testing.T) {
	tests := []struct {
		in   string
		want ARN
	}{
		{"arn:aws:iam::111111111111:role/app/deploy", ARN{"aws", "iam", "", "111111111111", "role/app/deploy"}},
		{"arn:aws:iam::aws:policy/AdministratorAccess", ARN{"aws", "iam", "", "aws", "policy/AdministratorAccess"}},
		{"arn:aws:lambda:us-east-1:111111111111:function:f:1", ARN{"aws", "lambda", "us-east-1", "111111111111", "function:f:1"}},
		{"arn:aws-cn:s3:::bucket/key", ARN{"aws-cn", "s3", "", "", "bucket/key"}},
		{"arn:aws:sts::111111111111:assumed-role/r/s", ARN{"aws", "sts", "", "111111111111", "assumed-role/r/s"}},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := Parse(tc.in)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if got != tc.want {
				t.Errorf("Parse() = %+v, want %+v", got, tc.want)
			}
			if got.String() != tc.in {
				t.Errorf("String() = %q, want round trip", got.String())
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{"", "*", "arn:aws:iam", "urn:aws:iam::1:x", "arn::iam::1:x", "arn:aws:::1:x", "arn:aws:iam::1:"} {
		t.Run(in, func(t *testing.T) {
			if _, err := Parse(in); err == nil {
				t.Errorf("Parse(%q) error = nil", in)
			}
		})
	}
}

func TestIsAccountID(t *testing.T) {
	for in, want := range map[string]bool{"111111111111": true, "11111111111": false, "1111111111111": false, "11111111111a": false, "": false} {
		if got := IsAccountID(in); got != want {
			t.Errorf("IsAccountID(%q) = %v", in, got)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add("arn:aws:iam::111111111111:role/x")
	f.Fuzz(func(t *testing.T, s string) {
		a, err := Parse(s)
		if err == nil && a.String() != s {
			t.Fatalf("round trip failed: %q -> %q", s, a.String())
		}
	})
}
