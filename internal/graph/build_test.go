package graph

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/brennocm/escalint/internal/snapshot"
)

const testSnapshot = `{
 "UserDetailList": [
  {"UserName":"alice","UserId":"AIDAALICE0000000000","Arn":"arn:aws:iam::111111111111:user/alice","Path":"/","GroupList":["admins"],
   "UserPolicyList":[]},
  {"UserName":"bob","UserId":"AIDABOB000000000000","Arn":"arn:aws:iam::111111111111:user/bob","Path":"/",
   "UserPolicyList":[{"PolicyName":"assume","PolicyDocument":{"Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}}}]},
  {"UserName":"carol","UserId":"AIDACAROL0000000000","Arn":"arn:aws:iam::111111111111:user/carol","Path":"/",
   "UserPolicyList":[{"PolicyName":"s3","PolicyDocument":{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}}],
   "PermissionsBoundary":{"PermissionsBoundaryType":"Policy","PermissionsBoundaryArn":"arn:aws:iam::111111111111:policy/S3Only"}}
 ],
 "GroupDetailList": [
  {"GroupName":"admins","GroupId":"AGPAADMINS000000000","Arn":"arn:aws:iam::111111111111:group/admins","Path":"/",
   "AttachedManagedPolicies":[{"PolicyName":"AdministratorAccess","PolicyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}]}
 ],
 "RoleDetailList": [
  {"RoleName":"DirectToAlice","RoleId":"AROADIRECT000000000","Arn":"arn:aws:iam::111111111111:role/DirectToAlice","Path":"/",
   "AssumeRolePolicyDocument":{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:user/alice"},"Action":"sts:AssumeRole"}},
   "RoleLastUsed":{"LastUsedDate":"2026-01-01T00:00:00Z"}},
  {"RoleName":"AccountTrust","RoleId":"AROAACCOUNT00000000","Arn":"arn:aws:iam::111111111111:role/AccountTrust","Path":"/",
   "AssumeRolePolicyDocument":{"Statement":{"Effect":"Allow","Principal":{"AWS":"111111111111"},"Action":"sts:AssumeRole"}},
   "RoleLastUsed":{"LastUsedDate":"2026-10-20T00:00:00Z"}},
  {"RoleName":"Everyone","RoleId":"AROAEVERYONE0000000","Arn":"arn:aws:iam::111111111111:role/Everyone","Path":"/",
   "AssumeRolePolicyDocument":{"Statement":{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}}},
  {"RoleName":"Vendor","RoleId":"AROAVENDOR000000000","Arn":"arn:aws:iam::111111111111:role/Vendor","Path":"/",
   "AssumeRolePolicyDocument":{"Statement":[
     {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":"sts:AssumeRole"},
     {"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"},
     {"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity",
      "Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:example-org/*"}}}]},
   "AttachedManagedPolicies":[{"PolicyName":"AdministratorAccess","PolicyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}]}
 ],
 "Policies": [
  {"PolicyName":"AdministratorAccess","Arn":"arn:aws:iam::aws:policy/AdministratorAccess","DefaultVersionId":"v1",
   "PolicyVersionList":[{"VersionId":"v1","IsDefaultVersion":true,"Document":{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}}]},
  {"PolicyName":"S3Only","Arn":"arn:aws:iam::111111111111:policy/S3Only","DefaultVersionId":"v1",
   "PolicyVersionList":[{"VersionId":"v1","IsDefaultVersion":true,"Document":{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}}]}
 ]
}`

var buildTime = time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)

func buildTest(t *testing.T) (*Graph, *Env) {
	t.Helper()
	snap, err := snapshot.Load(strings.NewReader(testSnapshot), snapshot.Options{})
	if err != nil {
		t.Fatalf("snapshot.Load() error = %v", err)
	}
	return Build(snap, Options{Now: buildTime})
}

func nodeByName(t *testing.T, g *Graph, kind NodeKind, name string) *Node {
	t.Helper()
	for _, n := range g.Nodes() {
		if n.Kind == kind && n.Name == name {
			return n
		}
	}
	t.Fatalf("no %s node named %q", kind, name)
	return nil
}

func edgeBetween(g *Graph, from, to *Node, kind EdgeKind) *Edge {
	return g.Edge(EdgeID(from.ID, to.ID, kind))
}

func TestBuildNodesAndFlags(t *testing.T) {
	g, _ := buildTest(t)
	alice := nodeByName(t, g, NodeUser, "alice")
	if alice.ID != NodeID("arn:aws:iam::111111111111:user/alice") || !reflect.DeepEqual(alice.Flags, []string{"no_boundary"}) {
		t.Errorf("alice = %+v", alice)
	}
	carol := nodeByName(t, g, NodeUser, "carol")
	if len(carol.Flags) != 0 {
		t.Errorf("carol has a boundary, flags = %v", carol.Flags)
	}
	if direct := nodeByName(t, g, NodeRole, "DirectToAlice"); !contains(direct.Flags, "stale") {
		t.Errorf("a role unused for 295 days must be stale, flags = %v", direct.Flags)
	}
	if acc := nodeByName(t, g, NodeRole, "AccountTrust"); contains(acc.Flags, "stale") {
		t.Errorf("a recently used role is not stale, flags = %v", acc.Flags)
	}
	if v := nodeByName(t, g, NodeRole, "Vendor"); !contains(v.Flags, "external_trust") {
		t.Errorf("Vendor trusts an external account, flags = %v", v.Flags)
	}
	nodeByName(t, g, NodeTier0Sink, "Effective admin")
	nodeByName(t, g, NodeExternalAccount, "999999999999")
	nodeByName(t, g, NodeService, "lambda.amazonaws.com")
	nodeByName(t, g, NodeFederated, "token.actions.githubusercontent.com")
	nodeByName(t, g, NodeAnyPrincipal, "*")
}

func TestBuildAssumeEdges(t *testing.T) {
	g, _ := buildTest(t)
	alice, bob, carol := nodeByName(t, g, NodeUser, "alice"), nodeByName(t, g, NodeUser, "bob"), nodeByName(t, g, NodeUser, "carol")
	direct, account, everyone := nodeByName(t, g, NodeRole, "DirectToAlice"), nodeByName(t, g, NodeRole, "AccountTrust"), nodeByName(t, g, NodeRole, "Everyone")

	// E13: the trust names alice, no identity policy needed.
	if e := edgeBetween(g, alice, direct, EdgeAssume); e == nil || e.Status != StatusAllowed || e.RuleIDs[0] != RuleAssume {
		t.Errorf("alice -> DirectToAlice = %+v", e)
	}
	if edgeBetween(g, bob, direct, EdgeAssume) != nil {
		t.Error("bob is not named by DirectToAlice")
	}
	// E16: account trust needs an identity allow: bob has one, carol not.
	if e := edgeBetween(g, bob, account, EdgeAssume); e == nil || e.Status != StatusAllowed {
		t.Errorf("bob -> AccountTrust = %+v", e)
	}
	if edgeBetween(g, carol, account, EdgeAssume) != nil {
		t.Error("carol has no sts:AssumeRole allow")
	}
	// E37 + MFA condition: everyone can assume, conditionally.
	e := edgeBetween(g, carol, everyone, EdgeAssume)
	if e == nil || e.Status != StatusConditional || !reflect.DeepEqual(e.ConditionsUnevaluated, []string{"aws:multifactorauthpresent"}) {
		t.Errorf("carol -> Everyone = %+v", e)
	}
	if edgeBetween(g, everyone, everyone, EdgeAssume) != nil {
		t.Error("self-assume edge created")
	}
}

func TestBuildTrustEdges(t *testing.T) {
	g, _ := buildTest(t)
	vendor := nodeByName(t, g, NodeRole, "Vendor")
	ext := nodeByName(t, g, NodeExternalAccount, "999999999999")
	if e := edgeBetween(g, ext, vendor, EdgeTrust); e == nil || e.Status != StatusAllowed {
		t.Errorf("external -> Vendor = %+v", e)
	}
	svc := nodeByName(t, g, NodeService, "lambda.amazonaws.com")
	if e := edgeBetween(g, svc, vendor, EdgeTrust); e == nil || e.Status != StatusAllowed {
		t.Errorf("lambda -> Vendor = %+v", e)
	}
	gh := nodeByName(t, g, NodeFederated, "token.actions.githubusercontent.com")
	e := edgeBetween(g, gh, vendor, EdgeTrust)
	if e == nil || e.Status != StatusConditional || e.RequiredActions[0] != "sts:AssumeRoleWithWebIdentity" {
		t.Errorf("github -> Vendor = %+v", e)
	}
	anyone := nodeByName(t, g, NodeAnyPrincipal, "*")
	if e := edgeBetween(g, anyone, nodeByName(t, g, NodeRole, "Everyone"), EdgeTrust); e == nil || e.Status != StatusConditional {
		t.Errorf("any -> Everyone = %+v", e)
	}
}

func TestBuildTier0AndMembership(t *testing.T) {
	g, _ := buildTest(t)
	sink := nodeByName(t, g, NodeTier0Sink, "Effective admin")
	alice, admins := nodeByName(t, g, NodeUser, "alice"), nodeByName(t, g, NodeGroup, "admins")
	vendor, carol := nodeByName(t, g, NodeRole, "Vendor"), nodeByName(t, g, NodeUser, "carol")
	for _, n := range []*Node{alice, admins, vendor} {
		if n.Tier != 0 || edgeBetween(g, n, sink, EdgeAdmin) == nil {
			t.Errorf("%s must be Tier 0 with an admin edge (tier %d)", n.Name, n.Tier)
		}
	}
	if carol.Tier == 0 || edgeBetween(g, carol, sink, EdgeAdmin) != nil {
		t.Error("carol only reads S3")
	}
	if e := edgeBetween(g, alice, admins, EdgeMemberOf); e == nil || e.Kind.Escalates() {
		t.Errorf("member_of = %+v", e)
	}
}

func TestBuildIsDeterministic(t *testing.T) {
	g1, _ := buildTest(t)
	for i := 0; i < 20; i++ {
		g2, _ := buildTest(t)
		if !reflect.DeepEqual(g1.Nodes(), g2.Nodes()) || !reflect.DeepEqual(g1.Edges(), g2.Edges()) {
			t.Fatalf("run %d differs", i)
		}
	}
}

func TestEdgeMerge(t *testing.T) {
	g := New()
	a := g.AddNode(&Node{Kind: NodeUser, Key: "a"})
	b := g.AddNode(&Node{Kind: NodeRole, Key: "b"})
	if g.AddNode(&Node{Kind: NodeUser, Key: "a", Name: "dup"}) != a {
		t.Fatal("AddNode must return the existing node")
	}
	g.AddEdge(&Edge{
		From: a.ID, To: b.ID, Kind: EdgePassRoleCompute, Status: StatusConditional, RuleIDs: []string{"EL-PE-022"},
		ConditionsUnevaluated: []string{"aws:sourceip"}, Latent: true,
	})
	e := g.AddEdge(&Edge{
		From: a.ID, To: b.ID, Kind: EdgePassRoleCompute, Status: StatusAllowed, RuleIDs: []string{"EL-PE-021"},
		RequiredActions: []string{"iam:PassRole", "ec2:RunInstances"},
	})
	if e.Status != StatusAllowed || !reflect.DeepEqual(e.RuleIDs, []string{"EL-PE-021", "EL-PE-022"}) || e.ConditionsUnevaluated != nil || e.Latent {
		t.Errorf("merged edge = %+v", e)
	}
	if !reflect.DeepEqual(e.RequiredActions, []string{"ec2:RunInstances", "iam:PassRole"}) {
		t.Errorf("actions not sorted: %v", e.RequiredActions)
	}
	if len(g.Edges()) != 1 || len(g.Out(a.ID)) != 1 || len(g.In(b.ID)) != 1 {
		t.Error("merge must not duplicate adjacency")
	}
	cut := g.RemoveEdges(map[string]bool{e.ID: true})
	if len(cut.Edges()) != 0 || len(cut.Nodes()) != 2 || len(g.Edges()) != 1 {
		t.Error("RemoveEdges must copy")
	}
}

func TestIDs(t *testing.T) {
	if first, again := NodeID("x"), NodeID("x"); first != again || NodeID("x") == NodeID("y") || !strings.HasPrefix(NodeID("x"), "n_") || len(NodeID("x")) != 18 {
		t.Error("NodeID")
	}
	if EdgeID("a", "b", EdgeAssume) == EdgeID("a", "b", EdgeTrust) || !strings.HasPrefix(PathID([]string{"e_1"}), "p_") {
		t.Error("EdgeID/PathID")
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
