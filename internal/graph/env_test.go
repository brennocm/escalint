package graph

import (
	"strings"
	"testing"

	"github.com/brennocm/escalint/internal/eval"
	"github.com/brennocm/escalint/internal/policy"
	"github.com/brennocm/escalint/internal/snapshot"
)

func loadEnvelope(t *testing.T) *snapshot.Snapshot {
	t.Helper()
	snap, err := snapshot.LoadFile("../snapshot/testdata/envelope.json", snapshot.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func TestEnvOrganizationChains(t *testing.T) {
	snap := loadEnvelope(t)
	g, env := Build(snap, Options{})
	if env.OrgID != "o-exampleorg1" || len(env.Notes()) != 0 {
		t.Fatalf("org = %q notes = %v", env.OrgID, env.Notes())
	}
	alice := nodeByName(t, g, NodeUser, "alice")
	pr := env.Principal(alice.ID)
	if pr.SCPs == nil || len(pr.SCPs.Levels) != 3 {
		t.Fatalf("SCP chain = %+v, want root, OU and account levels", pr.SCPs)
	}
	if got := len(pr.SCPs.Levels[1]); got != 2 {
		t.Errorf("OU level has %d SCPs, want FullAWSAccess and DenyLeaveOrg", got)
	}
	if pr.OrgID != "o-exampleorg1" {
		t.Errorf("OrgID = %q", pr.OrgID)
	}
	// DenyLeaveOrg is attached at the OU: the SCP decides.
	res := env.Ask(pr, "organizations:LeaveOrganization", "*", "", "", nil)
	if res.Decision != eval.ExplicitDeny || res.Decisive.Stage != eval.TypeSCP {
		t.Errorf("LeaveOrganization = %+v", res)
	}
	slr := env.Principal(nodeByName(t, g, NodeRole, "AWSServiceRoleForAutoScaling").ID)
	if slr.SCPs != nil {
		t.Error("service-linked roles must not get SCPs")
	}
	// RCPs apply to sts on roles of member accounts.
	lambdaAdmin := nodeByName(t, g, NodeRole, "LambdaExecAdmin")
	ext := &eval.Principal{Kind: eval.PrincipalExternal, Account: "999999999999"}
	if res := env.Ask(ext, "sts:AssumeRole", lambdaAdmin.ARN, lambdaAdmin.Account, lambdaAdmin.ID, nil); res.Decision != eval.ImplicitDeny {
		t.Errorf("external assume on a role that does not trust it = %s", res.Decision)
	}
}

func TestEnvManagementAccountAndMissingSCPs(t *testing.T) {
	snap := loadEnvelope(t)
	snap.Organization.ManagementAccountID = "111111111111"
	g, env := Build(snap, Options{})
	if env.Principal(nodeByName(t, g, NodeUser, "alice").ID).SCPs != nil {
		t.Error("management account principals must not get SCPs")
	}

	snap = loadEnvelope(t)
	var kept []snapshot.OrgPolicy
	for _, p := range snap.Organization.Policies {
		if p.Type != snapshot.PolicySCP {
			kept = append(kept, p)
		}
	}
	snap.Organization.Policies = kept
	g, env = Build(snap, Options{})
	if len(env.Notes()) != 1 || !strings.Contains(env.Notes()[0], "no SCPs") {
		t.Errorf("notes = %v", env.Notes())
	}
	if env.Principal(nodeByName(t, g, NodeUser, "alice").ID).SCPs != nil {
		t.Error("without SCPs in the snapshot the chain must be nil")
	}
}

func TestMayAllow(t *testing.T) {
	parse := func(text string) *policy.Document {
		d, err := policy.Parse([]byte(text), policy.KindIdentity, policy.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	tests := []struct {
		name string
		docs []*policy.Document
		want bool
	}{
		{"no policies", nil, false},
		{"unknown policy", []*policy.Document{nil}, true},
		{"allows", []*policy.Document{parse(`{"Statement":{"Effect":"Allow","Action":"sts:*","Resource":"*"}}`)}, true},
		{"not action excludes", []*policy.Document{parse(`{"Statement":{"Effect":"Allow","NotAction":"sts:*","Resource":"*"}}`)}, false},
		{"not action includes", []*policy.Document{parse(`{"Statement":{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}}`)}, true},
		{"deny only", []*policy.Document{parse(`{"Statement":{"Effect":"Deny","Action":"*","Resource":"*"}}`)}, false},
	}
	for _, tc := range tests {
		pr := &eval.Principal{}
		for _, d := range tc.docs {
			pr.Identity = append(pr.Identity, eval.Policy{Doc: d})
		}
		if got := MayAllow(pr, "sts:AssumeRole"); got != tc.want {
			t.Errorf("%s: mayAllow = %v, want %v", tc.name, got, tc.want)
		}
	}
	if MayAllow(nil, "x") {
		t.Error("nil principal")
	}
}

func TestHelpers(t *testing.T) {
	if entryAccount("999999999999") != "999999999999" || entryAccount("arn:aws:iam::222222222222:root") != "222222222222" || entryAccount("AROAX") != "" {
		t.Error("entryAccount")
	}
	if federatedName("arn:aws:iam::1:saml-provider/Okta") != "Okta" || federatedName("accounts.google.com") != "accounts.google.com" {
		t.Error("federatedName")
	}
	if StatusOf(eval.Allow) != StatusAllowed || StatusOf(eval.Conditional) != StatusConditional {
		t.Error("StatusOf")
	}
	if len(appendOnce([]string{"a"}, "a")) != 1 {
		t.Error("appendOnce")
	}
	g, _ := buildTest(t)
	if len(g.Sinks()) != 1 {
		t.Errorf("sinks = %d", len(g.Sinks()))
	}
	if tagMap(nil) != nil {
		t.Error("tagMap(nil)")
	}
}

func TestSAMLTrustUsesAssumeRoleWithSAML(t *testing.T) {
	in := `{"RoleDetailList":[{"RoleName":"r","Arn":"arn:aws:iam::111111111111:role/r","Path":"/",
		"AssumeRolePolicyDocument":{"Statement":{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::111111111111:saml-provider/Okta"},"Action":"sts:AssumeRoleWithSAML"}}}]}`
	snap, err := snapshot.Load(strings.NewReader(in), snapshot.Options{})
	if err != nil {
		t.Fatal(err)
	}
	g, _ := Build(snap, Options{Now: buildTime})
	fed := nodeByName(t, g, NodeFederated, "Okta")
	e := edgeBetween(g, fed, nodeByName(t, g, NodeRole, "r"), EdgeTrust)
	if e == nil || e.RequiredActions[0] != "sts:AssumeRoleWithSAML" || e.Status != StatusAllowed {
		t.Errorf("SAML trust edge = %+v", e)
	}
}
