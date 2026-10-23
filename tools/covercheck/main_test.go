package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseProfile(t *testing.T) {
	profile := `mode: atomic
github.com/brennocm/escalint/internal/eval/eval.go:1.1,2.2 4 1
github.com/brennocm/escalint/internal/eval/eval.go:3.1,4.2 6 0
github.com/brennocm/escalint/internal/eval/eval.go:3.1,4.2 6 2
github.com/brennocm/escalint/internal/cli/root.go:1.1,2.2 5 0
`
	got, err := parseProfile(strings.NewReader(profile))
	if err != nil {
		t.Fatalf("parseProfile() error = %v", err)
	}
	if c := got["internal/eval"]; c.statements != 10 || c.covered != 10 {
		t.Errorf("internal/eval = %+v, want 10/10 (duplicate block merged)", c)
	}
	if c := got["internal/cli"]; c.statements != 5 || c.covered != 0 {
		t.Errorf("internal/cli = %+v, want 0/5", c)
	}
}

func TestParseProfileErrors(t *testing.T) {
	tests := map[string]string{
		"no mode line":     "x.go:1.1,2.2 1 1\n",
		"wrong fields":     "mode: set\nx.go:1.1,2.2 1\n",
		"bad statements":   "mode: set\nx.go:1.1,2.2 a 1\n",
		"bad hits":         "mode: set\nx.go:1.1,2.2 1 b\n",
		"missing location": "mode: set\nnocolon 1 1\n",
	}
	for name, profile := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseProfile(strings.NewReader(profile)); err == nil {
				t.Fatal("parseProfile() error = nil, want error")
			}
		})
	}
}

func TestReport(t *testing.T) {
	tests := []struct {
		name   string
		input  map[string]counts
		wantOK bool
		want   string
	}{
		{
			name:   "all pass",
			input:  map[string]counts{"internal/eval": {statements: 10, covered: 10}},
			wantOK: true,
			want:   "| `internal/eval` | 100.0% | 90% | pass |",
		},
		{
			name:   "package below target",
			input:  map[string]counts{"internal/eval": {statements: 10, covered: 8}, "internal/cli": {statements: 90, covered: 90}},
			wantOK: false,
			want:   "| `internal/eval` | 80.0% | 90% | **FAIL** |",
		},
		{
			name:   "total below target",
			input:  map[string]counts{"internal/cli": {statements: 10, covered: 1}},
			wantOK: false,
			want:   "| **total** | 10.0% | 80% | **FAIL** |",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if ok := report(&out, tc.input); ok != tc.wantOK {
				t.Errorf("report() ok = %v, want %v\n%s", ok, tc.wantOK, out.String())
			}
			if !strings.Contains(out.String(), tc.want) {
				t.Errorf("report() output missing %q:\n%s", tc.want, out.String())
			}
		})
	}
}

func TestPercentEmptyPackage(t *testing.T) {
	if got := (counts{}).percent(); got != 100 {
		t.Errorf("percent() of empty package = %v, want 100", got)
	}
}

func TestRun(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.out")
	bad := filepath.Join(dir, "bad.out")
	if err := os.WriteFile(good, []byte("mode: set\nx.go:1.1,2.2 1 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		path string
		want int
	}{
		{"targets met", good, 0},
		{"malformed profile", bad, 2},
		{"missing file", filepath.Join(dir, "missing.out"), 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(tc.path, &stdout, &stderr); got != tc.want {
				t.Errorf("run() = %d, want %d (stderr %q)", got, tc.want, stderr.String())
			}
		})
	}
}
