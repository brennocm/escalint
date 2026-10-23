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

func TestReadmeRulesUpToDate(t *testing.T) {
	data, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	got, ok := ReplaceReadmeRules(string(data))
	if !ok {
		t.Fatal("README.md has no generated rules section")
	}
	if *updateDocs {
		// The path is a constant; the content is the generated table.
		if err := os.WriteFile("../../README.md", []byte(got), 0o600); err != nil { //nolint:gosec // G703 false positive
			t.Fatal(err)
		}
		return
	}
	if got != string(data) {
		t.Error("the rules table in README.md is stale; run make gen-docs")
	}
}

func TestReplaceReadmeRulesWithoutMarkers(t *testing.T) {
	if _, ok := ReplaceReadmeRules("# x\n"); ok {
		t.Error("replaced without markers")
	}
}
