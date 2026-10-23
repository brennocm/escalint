package rules

import (
	"flag"
	"os"
	"testing"
)

var updateDocs = flag.Bool("update-docs", false, "rewrite docs/coverage.md")

func TestCoverageDocUpToDate(t *testing.T) {
	got := CoverageMarkdown()
	if *updateDocs {
		if err := os.WriteFile("../../docs/coverage.md", []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile("../../docs/coverage.md")
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != got {
		t.Error("docs/coverage.md is stale; run make gen-docs")
	}
}
