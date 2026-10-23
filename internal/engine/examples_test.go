package engine

import (
	"testing"

	"github.com/brennocm/escalint/internal/graph"
	"github.com/brennocm/escalint/internal/rules"
)

// examples/vulnerable-account fires every stable rule; examples/hardened-account
// fires none. Both are permanent integration tests (project.md Phase 8).
func TestExampleAccounts(t *testing.T) {
	vulnerable := load(t, "../../examples/vulnerable-account/snapshot.json")
	cfg := rules.Config{ThirdPartyAccounts: []string{"222222222222"}}
	res := run(t, vulnerable, Options{Config: cfg})
	fired := map[string]int{}
	for _, f := range res.Findings {
		fired[f.RuleID]++
	}
	for _, r := range rules.All() {
		m := r.Meta()
		if m.Status != rules.Stable || m.ID == "EL-PARSE-003" {
			continue // EL-PARSE-003 comes from .escalint.yaml, not the snapshot
		}
		if fired[m.ID] == 0 {
			t.Errorf("%s does not fire on the vulnerable account", m.ID)
		}
	}
	if len(res.Paths) == 0 || len(res.FixPlan) == 0 {
		t.Error("vulnerable account has no paths or fix plan")
	}

	hardened := load(t, "../../examples/hardened-account/snapshot.json")
	clean := run(t, hardened, Options{Experimental: true, Config: rules.Config{
		TrustedAccounts: []string{"222222222222"}, ThirdPartyAccounts: []string{"999999999999"},
	}})
	for _, f := range clean.Findings {
		t.Errorf("hardened account finding: %s %s", f.RuleID, f.Message)
	}
	// The only path is the intended one: single sign-on (SAML, audience
	// pinned) into the admin role.
	for _, p := range clean.Paths {
		if n := clean.Graph.Node(p.Source); n == nil || n.Kind != graph.NodeFederated {
			t.Errorf("unexpected path from %+v", n)
		}
	}
}
