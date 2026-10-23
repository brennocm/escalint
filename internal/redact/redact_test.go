package redact

import (
	"bytes"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/brennocm/escalint/internal/contract"
	"github.com/brennocm/escalint/internal/engine"
	"github.com/brennocm/escalint/internal/snapshot"
	"github.com/brennocm/escalint/internal/synth"
)

var testKey = []byte("escalint-test-key-0123456789abcdef")

func fixed(t *testing.T) *Redactor {
	t.Helper()
	r, err := New(testKey)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestARN(t *testing.T) {
	r := fixed(t)
	a := r.ARN("arn:aws:iam::111111111111:role/teams/payments/deployer")
	if strings.Contains(a, "111111111111") || strings.Contains(a, "payments") || strings.Contains(a, "deployer") {
		t.Errorf("leaks: %s", a)
	}
	if !strings.HasPrefix(a, "arn:aws:iam::") || !strings.Contains(a, ":role/path-") || !strings.Contains(a, "/role-") {
		t.Errorf("shape lost: %s", a)
	}
	if r.ARN("arn:aws:iam::111111111111:role/teams/payments/deployer") != a {
		t.Error("not stable within a run")
	}
	acct := r.Account("111111111111")
	if len(acct) != 12 || !strings.Contains(a, ":"+acct+":") {
		t.Errorf("account %s not reused in %s", acct, a)
	}
	for _, keep := range []string{"arn:aws:iam::aws:policy/AdministratorAccess", "*", "", "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"} {
		got := r.ARN(keep)
		if keep == "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com" {
			if !strings.HasSuffix(got, "oidc-provider/token.actions.githubusercontent.com") || strings.Contains(got, "111111111111") {
				t.Errorf("public provider: %s", got)
			}
			continue
		}
		if got != keep {
			t.Errorf("ARN(%q) = %q", keep, got)
		}
	}
	if got := r.ARN("arn:aws:iam::111111111111:root"); got != "arn:aws:iam::"+acct+":root" {
		t.Errorf("root = %s", got)
	}
	if got := r.ARN("arn:aws:s3:::secret-bucket/key"); strings.Contains(got, "secret") {
		t.Errorf("s3 = %s", got)
	}
	if got := r.ARN("arn:aws:sns:us-east-1:111111111111:alerts"); strings.Contains(got, "alerts") {
		t.Errorf("sns = %s", got)
	}
	if got := r.ARN("not-an-arn"); got == "not-an-arn" {
		t.Error("non-ARN kept")
	}
	other, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	if other.ARN("arn:aws:iam::111111111111:role/teams/payments/deployer") == a {
		t.Error("random key gives the fixed key's pseudonym")
	}
}

func TestPolicySourceAndText(t *testing.T) {
	r := fixed(t)
	inline := r.PolicySource("inline:arn:aws:iam::111111111111:user/bob/keys")
	trust := r.PolicySource("trust:arn:aws:iam::111111111111:role/app")
	rewritten := r.PolicySource("rewritten-trust:arn:aws:iam::111111111111:role/app")
	scp := r.PolicySource("p-denyleave")
	for _, s := range []string{inline, trust, rewritten, scp} {
		if strings.Contains(s, "bob") || strings.Contains(s, "keys") || strings.Contains(s, ":role/app") || strings.Contains(s, "denyleave") {
			t.Errorf("leak: %s", s)
		}
	}
	if !strings.HasPrefix(inline, "inline:arn:aws:iam::") || !strings.HasPrefix(trust, "trust:arn:") || !strings.HasPrefix(rewritten, "rewritten-trust:arn:") {
		t.Errorf("prefixes lost: %s %s %s", inline, trust, rewritten)
	}
	r.Name("sid", "Pass")
	text := r.Text("arn:aws:iam::111111111111:user/bob can act as bob via Sid=Pass, account 222222222222 and 1234567890123; PassRole stays; bobby stays.")
	for _, leak := range []string{"111111111111", "user/bob ", " bob ", "Sid=Pass", "222222222222"} {
		if strings.Contains(text, leak) {
			t.Errorf("text leaks %q: %s", leak, text)
		}
	}
	for _, keep := range []string{"PassRole", "bobby", "1234567890123"} {
		if !strings.Contains(text, keep) {
			t.Errorf("text lost %q: %s", keep, text)
		}
	}
	if r.Text("") != "" || r.Path("/") != "/" || r.Name("user", "") != "" || r.ID("") != "" || r.Account("aws") != "aws" {
		t.Error("empty values must stay empty")
	}
	if got := r.ID("noprefix"); !strings.HasPrefix(got, "x_") {
		t.Errorf("ID without prefix = %s", got)
	}
	if got := r.PolicySource("inline:bare"); strings.Contains(got, "bare") {
		t.Errorf("inline without owner = %s", got)
	}
	if r.PolicySource("") != "" || r.PolicySource("arn:aws:iam::aws:policy/ReadOnlyAccess") != "arn:aws:iam::aws:policy/ReadOnlyAccess" {
		t.Error("policy source")
	}
}

func analysisOf(t interface {
	Fatal(...any)
	Helper()
}, data []byte,
) *contract.Analysis {
	t.Helper()
	snap, err := snapshot.Load(bytes.NewReader(data), snapshot.Options{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := engine.Run(snap, engine.Options{Experimental: true})
	if err != nil {
		t.Fatal(err)
	}
	a, err := contract.Build(res, contract.Meta{Deterministic: true})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// No identifier of a synthetic snapshot survives redaction of the analysis.
func TestPropertyNoIdentifierLeaks(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		gen, err := synth.Generate(synth.Options{
			Principals:     rapid.IntRange(4, 40).Draw(t, "principals"),
			Accounts:       rapid.IntRange(1, 3).Draw(t, "accounts"),
			Seed:           rapid.Uint64().Draw(t, "seed"),
			EscalationRate: 0.3,
			RandomNames:    true,
		})
		if err != nil {
			t.Fatal(err)
		}
		a := analysisOf(t, gen.JSON)
		ids := map[string]bool{}
		for _, n := range a.Nodes {
			ids[n.ID] = true
		}
		r, err := New(nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Analysis(a)
		out, err := contract.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range gen.Identifiers {
			if bytes.Contains(out, []byte(id)) {
				t.Fatalf("identifier %q survives redaction", id)
			}
		}
		for id := range ids {
			if bytes.Contains(out, []byte(id)) {
				t.Fatalf("original graph ID %q survives redaction", id)
			}
		}
		if !a.Snapshot.Redacted {
			t.Fatal("redacted flag not set")
		}
	})
}

// Redaction keeps the graph consistent: every reference resolves.
func TestReferencesStayConsistent(t *testing.T) {
	gen, err := synth.Generate(synth.Options{Principals: 40, Accounts: 2, Seed: 3, EscalationRate: 0.3, RandomNames: true})
	if err != nil {
		t.Fatal(err)
	}
	a := analysisOf(t, gen.JSON)
	before := len(a.Paths)
	fixed(t).Analysis(a)
	nodes, edges, paths := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, n := range a.Nodes {
		nodes[n.ID] = true
	}
	for _, e := range a.Edges {
		edges[e.ID] = true
		if !nodes[e.From] || !nodes[e.To] {
			t.Fatalf("edge %s dangles", e.ID)
		}
	}
	for _, p := range a.Paths {
		paths[p.ID] = true
		for _, e := range p.Edges {
			if !edges[e] {
				t.Fatalf("path %s uses unknown edge %s", p.ID, e)
			}
		}
	}
	for _, f := range a.Findings {
		if f.PathID != nil && !paths[*f.PathID] {
			t.Fatalf("finding %s points to unknown path", f.ID)
		}
		if f.EdgeID != nil && !edges[*f.EdgeID] {
			t.Fatalf("finding %s points to unknown edge", f.ID)
		}
	}
	for _, s := range a.FixPlan {
		if !edges[s.EdgeID] {
			t.Fatalf("fix step uses unknown edge")
		}
	}
	if before == 0 || len(a.Paths) != before {
		t.Errorf("paths %d -> %d", before, len(a.Paths))
	}
}

func TestOptionalSections(t *testing.T) {
	org, grp, exp := "o-secretorg", "payments-team", "2027-01-01"
	node := contract.Node{ID: "n_0000000000000001", Kind: "federated", Name: "corp-saml", Account: "111111111111", Group: &grp, Tags: map[string]string{"owner": "carol"}}
	finding := contract.Finding{ID: "f_0000000000000001", RuleID: "EL-PE-001", Severity: "high", Message: "carol did it", Suppressed: &contract.Suppressed{Reason: "carol approved", Source: ".escalint.yaml"}}
	a := &contract.Analysis{
		Snapshot:     contract.SnapshotInfo{Accounts: []string{"111111111111"}, Organization: &org},
		Nodes:        []contract.Node{node, {ID: "n_0000000000000002", Kind: "external_account", Name: "333333333333", Account: "333333333333"}},
		Findings:     []contract.Finding{finding},
		Groupings:    []contract.Grouping{{Name: grp, Nodes: []string{node.ID}}},
		Suppressions: []contract.Suppression{{Rule: "EL-PE-001", ARN: "arn:aws:iam::111111111111:user/carol*", Reason: "carol approved", Expires: &exp, Findings: []string{finding.ID}}},
		Notes:        []string{"account 111111111111 has no SCPs"},
		Diff: &contract.Diff{
			Added: contract.DiffItems{Nodes: []string{node.ID}},
			Removed: contract.DiffItems{Findings: []string{finding.ID}, Objects: &contract.Removed{
				Nodes: []contract.Node{node}, Findings: []contract.Finding{finding},
				Edges: []contract.Edge{{ID: "e_0000000000000001", From: node.ID, To: node.ID}},
				Paths: []contract.Path{{ID: "p_0000000000000001", Source: node.ID, Target: node.ID}},
			}},
		},
	}
	r := fixed(t)
	r.Name("user", "carol")
	r.Analysis(a)
	out, err := contract.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"secretorg", "payments-team", "carol", "corp-saml", "111111111111", "333333333333", "n_0000000000000001", "f_0000000000000001"} {
		if bytes.Contains(out, []byte(leak)) {
			t.Errorf("leaks %q:\n%s", leak, out)
		}
	}
	if !strings.HasPrefix(*a.Snapshot.Organization, "o-") {
		t.Errorf("organization = %s", *a.Snapshot.Organization)
	}
}
