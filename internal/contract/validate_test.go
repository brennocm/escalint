package contract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateIdentifiersAcceptsEngineOutput(t *testing.T) {
	files, err := filepath.Glob("testdata/*.analysis.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures: %v", err)
	}
	more, _ := filepath.Glob("../../web/src/data/fixtures/*.analysis.json")
	for _, f := range append(files, more...) {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var a Analysis
		if err := json.Unmarshal(data, &a); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if err := ValidateIdentifiers(&a); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

func TestValidateIdentifiersRejectsInjection(t *testing.T) {
	good := func() *Analysis {
		n, e, p, f := "n_0123456789abcdef", "e_0123456789abcdef", "p_0123456789abcdef", "f_0123456789abcdef"
		return &Analysis{
			Nodes:    []Node{{ID: n, Kind: "role"}},
			Edges:    []Edge{{ID: e, From: n, To: n, Kind: "assume", Status: "allowed", RuleIDs: []string{"EL-PE-014"}}},
			Paths:    []Path{{ID: p, Source: n, Target: n, Status: "allowed", Severity: "high", Edges: []string{e}, Nodes: []string{n}}},
			Findings: []Finding{{ID: f, RuleID: "EL-PE-014", Severity: "high", NodeID: &n, EdgeID: &e, PathID: &p}},
			Diff:     &Diff{Removed: DiffItems{Objects: &Removed{Nodes: []Node{{ID: n, Kind: "user"}}}}},
		}
	}
	if err := ValidateIdentifiers(good()); err != nil {
		t.Fatal(err)
	}
	evil := "n_0\nclick n_0 \"javascript:alert(1)\""
	mutations := map[string]func(a *Analysis){
		"node id":     func(a *Analysis) { a.Nodes[0].ID = evil },
		"node kind":   func(a *Analysis) { a.Nodes[0].Kind = "role\x1b[2J" },
		"edge from":   func(a *Analysis) { a.Edges[0].From = evil },
		"edge rule":   func(a *Analysis) { a.Edges[0].RuleIDs = []string{"EL-PE-014\n"} },
		"path id":     func(a *Analysis) { a.Paths[0].ID = "p_x" },
		"path status": func(a *Analysis) { a.Paths[0].Status = "Allowed!" },
		"finding":     func(a *Analysis) { a.Findings[0].RuleID = "\x1b]8;;http://x\x07" },
		"diff node":   func(a *Analysis) { a.Diff.Removed.Objects.Nodes[0].ID = evil },
	}
	for name, mutate := range mutations {
		a := good()
		mutate(a)
		err := ValidateIdentifiers(a)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.ContainsAny(err.Error(), "\n\x1b\x07") {
			t.Errorf("%s: the error carries control characters: %q", name, err)
		}
	}
	a := good()
	a.Nodes[0].ID, a.Edges[0].ID = "x", "y"
	if err := ValidateIdentifiers(a); err == nil || !strings.Contains(err.Error(), "and 1 more") {
		t.Errorf("multiple errors = %v", err)
	}
	if got := clip(strings.Repeat("a", 50)); len(got) > 45 {
		t.Errorf("clip = %q", got)
	}
}
