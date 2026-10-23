package config

import (
	"errors"
	"strings"
	"testing"
)

// FuzzDecode: .escalint.yaml may come from a pull request, so any input must
// either decode into a valid configuration or fail with ErrInvalid, never
// panic or hang (anchors and aliases are rejected: no billion laughs).
func FuzzDecode(f *testing.F) {
	f.Add(valid)
	f.Add("version: 1\n")
	f.Add("a: &x [1]\nb: *x\n")
	f.Add("version: 1\nsuppressions:\n  - rule: \"*\"\n    arn: \"*\"\n    reason: r\n    expires: 2027-01-31\n")
	f.Add("\ufeffversion: 1\n")
	f.Fuzz(func(t *testing.T, s string) {
		cfg, err := Decode(strings.NewReader(s))
		if err != nil {
			if !errors.Is(err, ErrInvalid) && !strings.Contains(err.Error(), "read") {
				t.Fatalf("error without ErrInvalid: %v", err)
			}
			return
		}
		if cfg == nil {
			t.Fatal("nil configuration without an error")
		}
		if err := cfg.validate(); err != nil {
			t.Fatalf("decoded configuration does not validate: %v", err)
		}
	})
}
