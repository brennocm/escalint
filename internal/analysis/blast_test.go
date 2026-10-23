package analysis

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/brennocm/escalint/internal/catalog"
	"github.com/brennocm/escalint/internal/eval"
	"github.com/brennocm/escalint/internal/graph"
	"github.com/brennocm/escalint/internal/snapshot"
)

const blastSnapshot = `{
 "UserDetailList": [
  {"UserName":"admin","Arn":"arn:aws:iam::111111111111:user/admin","Path":"/",
   "UserPolicyList":[{"PolicyName":"all","PolicyDocument":{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}}]},
  {"UserName":"reader","Arn":"arn:aws:iam::111111111111:user/reader","Path":"/",
   "UserPolicyList":[{"PolicyName":"r","PolicyDocument":{"Statement":[
     {"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::app/*"},
     {"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}]}}]},
  {"UserName":"passer","Arn":"arn:aws:iam::111111111111:user/passer","Path":"/",
   "UserPolicyList":[{"PolicyName":"p","PolicyDocument":{"Statement":{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::111111111111:role/app-*"}}}]},
  {"UserName":"secrets","Arn":"arn:aws:iam::111111111111:user/secrets","Path":"/",
   "UserPolicyList":[{"PolicyName":"s","PolicyDocument":{"Statement":{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"*"}}}]},
  {"UserName":"nothing","Arn":"arn:aws:iam::111111111111:user/nothing","Path":"/"},
  {"UserName":"poweruser","Arn":"arn:aws:iam::111111111111:user/poweruser","Path":"/",
   "UserPolicyList":[{"PolicyName":"pu","PolicyDocument":{"Statement":{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}}}]}
 ],
 "RoleDetailList": [
  {"RoleName":"Writer","Arn":"arn:aws:iam::111111111111:role/Writer","Path":"/",
   "AssumeRolePolicyDocument":{"Statement":{"Effect":"Allow","Principal":{"AWS":"111111111111"},"Action":"sts:AssumeRole"}},
   "RolePolicyList":[{"PolicyName":"w","PolicyDocument":{"Statement":{"Effect":"Allow","Action":["s3:PutObject","dynamodb:PutItem"],"Resource":"*"}}}]}
 ]
}`

func buildBlast(t *testing.T) (*graph.Graph, *CapabilityFinder) {
	t.Helper()
	snap, err := snapshot.Load(strings.NewReader(blastSnapshot), snapshot.Options{})
	if err != nil {
		t.Fatal(err)
	}
	g, env := graph.Build(snap, graph.Options{Now: time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)})
	c, err := catalog.Default()
	if err != nil {
		t.Fatal(err)
	}
	return g, NewCapabilityFinder(c, env)
}

func userNode(t *testing.T, g *graph.Graph, name string) *graph.Node {
	t.Helper()
	for _, n := range g.Nodes() {
		if n.Name == name {
			return n
		}
	}
	t.Fatalf("no node %s", name)
	return nil
}

func TestCapabilities(t *testing.T) {
	g, f := buildBlast(t)
	admin := f.For(userNode(t, g, "admin").ID)
	if admin["iam"] != ClassPermissionManagement || admin["s3"] != ClassPermissionManagement || len(admin) < 300 {
		t.Errorf("admin capabilities: iam=%q s3=%q services=%d", admin["iam"], admin["s3"], len(admin))
	}
	reader := f.For(userNode(t, g, "reader").ID)
	if !reflect.DeepEqual(reader, Capabilities{"s3": ClassRead, "sts": ClassWrite}) {
		t.Errorf("reader = %v", reader)
	}
	pu := f.For(userNode(t, g, "poweruser").ID)
	if _, ok := pu["iam"]; ok || pu["s3"] != ClassPermissionManagement {
		t.Errorf("NotAction iam:* must exclude iam and include s3 permission management, got iam=%q s3=%q", pu["iam"], pu["s3"])
	}
	if got := f.For(userNode(t, g, "nothing").ID); len(got) != 0 {
		t.Errorf("nothing = %v", got)
	}
	if f.For("n_unknown") != nil {
		t.Error("non-principal nodes have no capabilities")
	}
	// The cache returns the same answer.
	if !reflect.DeepEqual(f.For(userNode(t, g, "reader").ID), reader) {
		t.Error("cache changed the answer")
	}
}

func TestBlastRadiusIncludesReachablePrincipals(t *testing.T) {
	g, f := buildBlast(t)
	reader := userNode(t, g, "reader")
	b := BlastRadius(g, f, reader.ID, DefaultMaxDepth)
	if b.ReachablePrincipals != 1 || b.ReachesTier0 {
		t.Errorf("reader blast = %+v", b)
	}
	if !reflect.DeepEqual(b.Capabilities[ClassWrite], []string{"dynamodb", "s3", "sts"}) {
		t.Errorf("write services = %v (the Writer role is reachable)", b.Capabilities[ClassWrite])
	}
	admin := BlastRadius(g, f, userNode(t, g, "admin").ID, DefaultMaxDepth)
	if !admin.ReachesTier0 {
		t.Error("an admin reaches Tier 0")
	}
}

func TestAssignTiers(t *testing.T) {
	g, f := buildBlast(t)
	paths := Enumerate(g, PathOptions{})
	AssignTiers(g, paths, TierInputs{Finder: f, Primitives: []string{"iam:PassRole", "iam:CreateAccessKey"}})
	wantTier := map[string]int{
		"admin": 0, "passer": 2, "secrets": 2, "nothing": 3, "reader": 3, "Effective admin": 0,
		"poweruser": 2, // permission management outside IAM (s3:PutBucketPolicy…)
	}
	for name, tier := range wantTier {
		if got := userNode(t, g, name).Tier; got != tier {
			t.Errorf("%s tier = %d, want %d", name, got, tier)
		}
	}
	AssignTiers(g, paths, TierInputs{})
	if userNode(t, g, "secrets").Tier != 3 {
		t.Error("without a finder no principal can be Tier 2")
	}
}

func TestTier1FromPaths(t *testing.T) {
	tg := lineGraph()
	paths := Enumerate(tg.g, PathOptions{})
	AssignTiers(tg.g, paths, TierInputs{})
	if tg.nodes["a"].Tier != 1 || tg.nodes["b"].Tier != 1 || tg.nodes["c"].Tier != 0 {
		t.Errorf("tiers a=%d b=%d c=%d", tg.nodes["a"].Tier, tg.nodes["b"].Tier, tg.nodes["c"].Tier)
	}
}

func TestCacheKeyIsPersonalWithConditions(t *testing.T) {
	plain := &eval.Principal{ARN: "a", Account: "1", Identity: []eval.Policy{{Source: "p"}}}
	other := &eval.Principal{ARN: "b", Account: "1", Identity: []eval.Policy{{Source: "p"}}}
	if cacheKey(plain) != cacheKey(other) {
		t.Error("principals with the same policies must share a cache entry")
	}
	if !containsVariable("arn:aws:s3:::${aws:username}") || containsVariable("arn:aws:s3:::x") {
		t.Error("containsVariable")
	}
}

func TestClassOf(t *testing.T) {
	for level, want := range map[catalog.AccessLevel]Class{
		catalog.PermissionManagement: ClassPermissionManagement, catalog.Write: ClassWrite, catalog.Tagging: ClassWrite,
		catalog.Read: ClassRead, catalog.List: ClassList, catalog.AccessLevel("x"): ClassRead,
	} {
		if got := classOf(level); got != want {
			t.Errorf("classOf(%q) = %q", level, got)
		}
	}
	if rank(Class("x")) != len(classOrder) {
		t.Error("rank of unknown class")
	}
}

func TestBlastAllMatchesBlastRadius(t *testing.T) {
	g, f := buildBlast(t)
	// A cycle between two roles exercises the strongly connected branch.
	all := BlastAll(g, f)
	for _, n := range g.Nodes() {
		want := BlastRadius(g, f, n.ID, 1<<20)
		got, ok := all[n.ID]
		if !isPrincipal(n) {
			if ok {
				t.Errorf("non-principal %s has a blast radius", n.Name)
			}
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: BlastAll %+v, BlastRadius %+v", n.Name, got, want)
		}
	}
}

func TestTarjanIntCycles(t *testing.T) {
	// 0 -> 1 -> 2 -> 0, 2 -> 3, 4 -> 4
	adj := [][]int32{{1}, {2}, {0, 3}, {}, {4}}
	comp, comps := tarjanInt(adj)
	if comp[0] != comp[1] || comp[1] != comp[2] || comp[3] == comp[0] || len(comps) != 3 {
		t.Errorf("comp = %v comps = %v", comp, comps)
	}
	if comp[3] > comp[0] {
		t.Error("successor component must complete first")
	}
	if !selfLoop(adj, 4) || selfLoop(adj, 3) {
		t.Error("self loop detection")
	}
}
