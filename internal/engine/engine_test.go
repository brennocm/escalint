package engine

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/brennocm/escalint/internal/analysis"
	"github.com/brennocm/escalint/internal/graph"
	"github.com/brennocm/escalint/internal/rules"
	"github.com/brennocm/escalint/internal/snapshot"
	"github.com/brennocm/escalint/internal/synth"
)

func load(t *testing.T, path string) *snapshot.Snapshot {
	t.Helper()
	snap, err := snapshot.LoadFile(path, snapshot.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func fixture(t *testing.T, rule, variant string) *snapshot.Snapshot {
	t.Helper()
	return load(t, "../rules/testdata/"+rule+"/"+variant+"/snapshot.json")
}

func run(t *testing.T, snap *snapshot.Snapshot, opts Options) *Result {
	t.Helper()
	res, err := Run(snap, opts)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func byRule(res *Result, id string) []Finding {
	var out []Finding
	for _, f := range res.Findings {
		if f.RuleID == id {
			out = append(out, f)
		}
	}
	return out
}

func TestSelfEscalationEndToEnd(t *testing.T) {
	res := run(t, fixture(t, "EL-PE-004", "vulnerable"), Options{})
	got := byRule(res, "EL-PE-004")
	if len(got) != 1 {
		t.Fatalf("EL-PE-004 findings = %+v", got)
	}
	f := got[0]
	if f.Severity != rules.Critical || f.PathID == "" || !strings.HasPrefix(f.ID, "f_") || len(f.ID) != 18 {
		t.Errorf("finding = %+v", f)
	}
	if f.Location.Policy == "" || f.Location.Statement < 0 || f.Remediation == "" {
		t.Errorf("location/remediation = %+v", f)
	}
	if len(res.Paths) == 0 || len(res.FixPlan) == 0 {
		t.Fatalf("paths %d, fix plan %d", len(res.Paths), len(res.FixPlan))
	}
	step := res.FixPlan[0]
	if step.Target == "" || !strings.Contains(step.Change, "iam:AttachUserPolicy") {
		t.Errorf("fix step = %+v", step)
	}
	if src := res.Graph.Node(f.NodeID); src == nil || src.Tier != 1 {
		t.Errorf("attacker tier = %+v", src)
	}
	if b, ok := res.Blast[f.NodeID]; !ok || !b.ReachesTier0 {
		t.Errorf("blast = %+v", b)
	}
}

func TestSafeFixtureHasNoPathFindings(t *testing.T) {
	res := run(t, fixture(t, "EL-PE-004", "safe"), Options{})
	if got := byRule(res, "EL-PE-004"); len(got) != 0 {
		t.Errorf("safe fixture findings = %+v", got)
	}
}

func TestDisableRule(t *testing.T) {
	res := run(t, fixture(t, "EL-PE-004", "vulnerable"), Options{Disable: []string{"EL-PE-004"}})
	if got := byRule(res, "EL-PE-004"); len(got) != 0 {
		t.Errorf("disabled rule reported: %+v", got)
	}
}

func TestDisableAssumeRemovesAssumeEdges(t *testing.T) {
	snap := fixture(t, "EL-PE-014", "vulnerable")
	if got := byRule(run(t, snap, Options{}), "EL-PE-014"); len(got) == 0 {
		t.Fatal("EL-PE-014 not reported")
	}
	res := run(t, snap, Options{Disable: []string{"EL-PE-014"}})
	for _, e := range res.Graph.Edges() {
		if e.Kind == graph.EdgeAssume {
			t.Errorf("assume edge kept: %+v", e)
		}
	}
	if len(byRule(res, "EL-PE-014")) != 0 {
		t.Error("disabled assume rule reported")
	}
}

func TestSelect(t *testing.T) {
	ids := func(list []rules.Rule) string {
		var out []string
		for _, r := range list {
			out = append(out, r.Meta().ID)
		}
		return strings.Join(out, ",")
	}
	def, err := Select(Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range def {
		if r.Meta().Status != rules.Stable {
			t.Errorf("experimental rule %s enabled by default", r.Meta().ID)
		}
	}
	got, err := Select(Options{Enable: []string{"EL-PE-026"}, Disable: []string{"EL-PE-0??", "EL-PARSE-*", "EL-TR-*"}})
	if err != nil {
		t.Fatal(err)
	}
	if ids(got) != "" {
		t.Errorf("disable should win over enable: %s", ids(got))
	}
	got, err = Select(Options{Enable: []string{"EL-PE-026"}, Disable: []string{"EL-PE-00?", "EL-PE-01?", "EL-PE-02[0-5]", "EL-PARSE-*"}})
	if err == nil {
		t.Errorf("bracket pattern accepted: %s", ids(got))
	}
	if _, err := Select(Options{Disable: []string{"EL-XX-001"}}); !errors.Is(err, ErrUnknownRule) {
		t.Errorf("unknown rule: err = %v", err)
	}
	exp, err := Select(Options{Experimental: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(exp) != len(rules.All()) {
		t.Errorf("experimental selects %d of %d", len(exp), len(rules.All()))
	}
}

func TestMinSeverity(t *testing.T) {
	snap := load(t, "../snapshot/testdata/authz-diagnostics.json")
	all := run(t, snap, Options{})
	if len(byRule(all, "EL-PARSE-001")) != 1 {
		t.Fatalf("parse finding missing: %+v", all.Findings)
	}
	high := run(t, snap, Options{MinSeverity: rules.High})
	for _, f := range high.Findings {
		if f.Severity.Rank() > rules.High.Rank() {
			t.Errorf("finding below min severity: %+v", f)
		}
	}
}

func TestFindingsSorted(t *testing.T) {
	res := run(t, fixture(t, "EL-PE-015", "vulnerable"), Options{})
	for i := 1; i < len(res.Findings); i++ {
		a, b := res.Findings[i-1], res.Findings[i]
		if a.Severity.Rank() > b.Severity.Rank() || (a.Severity == b.Severity && a.RuleID > b.RuleID) || a.ID == b.ID {
			t.Errorf("findings out of order: %s/%s before %s/%s", a.RuleID, a.ID, b.RuleID, b.ID)
		}
	}
}

func dump(res *Result) string {
	var b strings.Builder
	for _, f := range res.Findings {
		fmt.Fprintf(&b, "%+v\n", f)
	}
	for _, p := range res.Paths {
		fmt.Fprintf(&b, "%+v\n", p)
	}
	for _, s := range res.FixPlan {
		fmt.Fprintf(&b, "%+v\n", s)
	}
	for _, n := range res.Graph.Nodes() {
		fmt.Fprintf(&b, "%s %d %v %+v\n", n.ID, n.Tier, n.Flags, res.Blast[n.ID])
	}
	return b.String()
}

func TestDeterministic(t *testing.T) {
	snap := fixture(t, "EL-PE-020", "vulnerable")
	want := dump(run(t, snap, Options{}))
	for range 20 {
		if got := dump(run(t, snap, Options{})); got != want {
			t.Fatalf("nondeterministic output:\n%s\nvs\n%s", got, want)
		}
	}
}

func TestChangeFor(t *testing.T) {
	g := graph.New()
	a := g.AddNode(&graph.Node{Kind: graph.NodeUser, Key: "arn:aws:iam::111111111111:user/a", ARN: "arn:aws:iam::111111111111:user/a", Account: "111111111111"})
	r := g.AddNode(&graph.Node{Kind: graph.NodeRole, Key: "arn:aws:iam::111111111111:role/r", ARN: "arn:aws:iam::111111111111:role/r", Account: "111111111111"})
	sink := g.AddNode(&graph.Node{Kind: graph.NodeTier0Sink, Key: graph.SinkKey("111111111111"), Account: "111111111111"})
	ev := func(action, policy, sid string) []graph.Evidence {
		return []graph.Evidence{{Principal: a.ID, Action: action, Policy: policy, Statement: 2, Sid: sid, Effect: "Allow", Stage: "identity"}}
	}
	cases := []struct {
		edge      *graph.Edge
		want, tgt string
	}{
		{&graph.Edge{From: a.ID, To: r.ID, Kind: graph.EdgePassRoleCompute, RequiredActions: []string{"iam:PassRole"}, Evidence: ev("iam:PassRole", "arn:aws:iam::111111111111:policy/P", "Pass")}, "Scope iam:PassRole in statement Sid=Pass", "arn:aws:iam::111111111111:policy/P#2"},
		{&graph.Edge{From: a.ID, To: r.ID, Kind: graph.EdgeTrust, Evidence: []graph.Evidence{{Principal: r.ID, Policy: "trust:" + r.ARN, Statement: 0, Stage: "resource"}}}, "trust policy of arn:aws:iam::111111111111:role/r", "trust:arn:aws:iam::111111111111:role/r#0"},
		{&graph.Edge{From: a.ID, To: sink.ID, Kind: graph.EdgeAdmin, Evidence: ev("iam:PutRolePolicy", "inline:x/y", "")}, "administrator access granted to arn:aws:iam::111111111111:user/a by statement #2", "inline:x/y#2"},
		{&graph.Edge{From: a.ID, To: r.ID, Kind: graph.EdgeCredential, RequiredActions: []string{"iam:CreateAccessKey"}}, "Remove the permissions that let", ""},
		{&graph.Edge{From: a.ID, To: r.ID, Kind: graph.EdgeModifyTrust, Evidence: ev("iam:UpdateAssumeRolePolicy", "inline:x/y", "")}, "Remove iam:UpdateAssumeRolePolicy from statement #2 of inline:x/y", "inline:x/y#2"},
	}
	for _, c := range cases {
		change, target := ChangeFor(g, c.edge)
		if !strings.Contains(change, c.want) || target != c.tgt {
			t.Errorf("%s: change %q target %q", c.edge.Kind, change, target)
		}
	}
	if c, tg := ChangeFor(g, nil); c != "" || tg != "" {
		t.Error("nil edge")
	}
	cond := &graph.Edge{
		From: a.ID, To: sink.ID, Kind: graph.EdgeModifyPermissions, Latent: true, Actor: r.ID, Status: graph.StatusConditional,
		RequiredActions: []string{"iam:AttachRolePolicy"}, ConditionsUnevaluated: []string{"aws:SourceIp"}, PrerequisitesUnverified: []string{"a cluster exists"},
	}
	msg := edgeMessage(g, cond, cond.RequiredActions)
	for _, want := range []string{"can modify the permissions of", "effective admin of account 111111111111", "performed by", "aws:SourceIp", "a cluster exists"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q lacks %q", msg, want)
		}
	}
	if loc := locationOf(g, &graph.Edge{From: a.ID}); loc.Entity != a.ARN || loc.Statement != -1 {
		t.Errorf("location without evidence = %+v", loc)
	}
}

// BlastAll (condensation) agrees with one unlimited BFS per node.
func TestBlastAllMatchesBFS(t *testing.T) {
	for seed := range uint64(4) {
		gen, err := synth.Generate(synth.Options{Principals: 60, Accounts: 2, Seed: seed, EscalationRate: 0.4})
		if err != nil {
			t.Fatal(err)
		}
		snap, err := snapshot.Load(bytes.NewReader(gen.JSON), snapshot.Options{})
		if err != nil {
			t.Fatal(err)
		}
		res := run(t, snap, Options{})
		finder := analysis.NewCapabilityFinder(res.Catalog, res.Env)
		for _, n := range res.Graph.Nodes() {
			want, ok := res.Blast[n.ID]
			if n.Kind != graph.NodeUser && n.Kind != graph.NodeRole && n.Kind != graph.NodeGroup {
				if ok {
					t.Errorf("blast for non-principal %s", n.ID)
				}
				continue
			}
			got := analysis.BlastRadius(res.Graph, finder, n.ID, 1<<20)
			if fmt.Sprint(got) != fmt.Sprint(want) {
				t.Fatalf("seed %d node %s: BFS %+v, BlastAll %+v", seed, n.Name, got, want)
			}
		}
	}
}
