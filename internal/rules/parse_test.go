package rules

import (
	"testing"

	"github.com/brennocm/escalint/internal/graph"
	"github.com/brennocm/escalint/internal/snapshot"
)

func TestParseRules(t *testing.T) {
	snap, err := snapshot.LoadFile("../snapshot/testdata/authz-diagnostics.json", snapshot.Options{})
	if err != nil {
		t.Fatal(err)
	}
	g, env := graph.Build(snap, graph.Options{})
	ctx := &Context{Graph: g, Env: env, Snap: snap}
	parse := elParse001().Apply(ctx)
	if len(parse) != 1 || parse[0].Severity != Info || parse[0].Location.Policy != "broken" || parse[0].Location.Path != "Statement.Effect" || parse[0].NodeID == "" {
		t.Errorf("EL-PARSE-001 findings = %+v", parse)
	}
	unresolved := elParse002().Apply(ctx)
	if len(unresolved) != 2 {
		t.Errorf("EL-PARSE-002 findings = %+v", unresolved)
	}
	clean, err := snapshot.LoadFile("../snapshot/testdata/authz-cli.json", snapshot.Options{})
	if err != nil {
		t.Fatal(err)
	}
	g, env = graph.Build(clean, graph.Options{})
	if got := elParse001().Apply(&Context{Graph: g, Env: env, Snap: clean}); len(got) != 0 {
		t.Errorf("clean snapshot has parse findings: %+v", got)
	}
}
