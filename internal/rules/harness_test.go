package rules

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/brennocm/escalint/internal/catalog"
	"github.com/brennocm/escalint/internal/graph"
	"github.com/brennocm/escalint/internal/snapshot"
)

var update = flag.Bool("update", false, "rewrite testdata fixtures")

const acct = "111111111111"

// scenario describes a small account built for one rule.
type scenario struct {
	users, groups, roles, policies []map[string]any
	resources                      map[string]any
	scpDeny                        []string // actions denied by an SCP at the account level
}

func arnOf(kind, name string) string { return "arn:aws:iam::" + acct + ":" + kind + "/" + name }

func statement(actions []string) map[string]any {
	return map[string]any{"Effect": "Allow", "Action": actions, "Resource": "*"}
}

func doc(stmts ...map[string]any) map[string]any {
	list := make([]any, 0, len(stmts))
	for _, s := range stmts {
		list = append(list, s)
	}
	return map[string]any{"Version": "2012-10-17", "Statement": list}
}

func inline(name string, d map[string]any) []any {
	return []any{map[string]any{"PolicyName": name, "PolicyDocument": d}}
}

func trustFor(principal map[string]any) map[string]any {
	return doc(map[string]any{"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"})
}

// variant mutates the actor's permissions.
type variant struct {
	name         string
	noPolicy     bool
	deny         bool
	boundary     bool
	scp          bool
	conditional  bool
	secondActor  bool
	wantEdges    int
	wantStatus   graph.Status // "" = any
	writeFixture string       // "vulnerable" or "safe"
}

var variants = []variant{
	{name: "positive", wantEdges: 1, writeFixture: "vulnerable"},
	{name: "negative", noPolicy: true, wantEdges: 0, writeFixture: "safe"},
	{name: "blocked by deny", deny: true, wantEdges: 0},
	{name: "blocked by boundary", boundary: true, wantEdges: 0},
	{name: "blocked by SCP", scp: true, wantEdges: 0},
	{name: "conditional", conditional: true, wantEdges: 1, wantStatus: graph.StatusConditional},
	{name: "multiple occurrences", secondActor: true, wantEdges: 2},
}

// actorKind picks who acts for a rule.
func actorKind(r Rule) string {
	switch x := r.(type) {
	case selfRule:
		if len(x.kinds) == 1 && x.kinds[0] == graph.NodeRole {
			return "role"
		}
	case assumeRule:
		return "role" // a role named in a trust is limited by its boundary (E14)
	}
	return "user"
}

// build creates the scenario of rule r for variant v.
func build(r Rule, v variant) scenario {
	m := r.Meta()
	sc := scenario{}
	actions := m.RequiredActions
	allow := statement(actions)
	if v.conditional {
		allow["Condition"] = map[string]any{"Bool": map[string]any{"aws:MultiFactorAuthPresent": "true"}}
	}
	stmts := []map[string]any{allow}
	if v.deny {
		// Deny every required action: some rules accept any one of several
		// (EL-PE-020), so denying only the first would leave a real path.
		stmts = append(stmts, map[string]any{"Effect": "Deny", "Action": actions, "Resource": "*"})
	}
	actorNames := []string{"attacker"}
	if v.secondActor {
		actorNames = append(actorNames, "attacker2")
	}
	kind := actorKind(r)

	addActor := func(name string) {
		entity := map[string]any{"Path": "/"}
		if !v.noPolicy {
			entity[map[string]string{"user": "UserPolicyList", "role": "RolePolicyList"}[kind]] = inline("p", doc(stmts...))
		}
		if v.boundary {
			entity["PermissionsBoundary"] = map[string]any{"PermissionsBoundaryType": "Policy", "PermissionsBoundaryArn": arnOf("policy", "S3Only")}
		}
		if kind == "user" {
			entity["UserName"], entity["Arn"], entity["UserId"] = name, arnOf("user", name), "AIDA"+strings.ToUpper(name)
		} else {
			entity["RoleName"], entity["Arn"], entity["RoleId"] = name, arnOf("role", name), "AROA"+strings.ToUpper(name)
			entity["AssumeRolePolicyDocument"] = trustFor(map[string]any{"Service": "ec2.amazonaws.com"})
		}
		if x, ok := r.(selfRule); ok {
			setupSelf(&sc, x, entity, name, v)
		}
		if kind == "user" {
			sc.users = append(sc.users, entity)
		} else {
			sc.roles = append(sc.roles, entity)
		}
	}
	for _, n := range actorNames {
		addActor(n)
	}
	sc.policies = append(sc.policies, managed("S3Only", doc(statement([]string{"s3:*"}))))
	if v.scp {
		sc.scpDeny = actions
	}

	switch x := r.(type) {
	case pairRule:
		switch x.targetKind {
		case graph.NodeUser:
			sc.users = append(sc.users, map[string]any{"UserName": "victim", "Arn": arnOf("user", "victim"), "Path": "/"})
		case graph.NodeGroup:
			sc.groups = append(sc.groups, map[string]any{"GroupName": "admins", "Arn": arnOf("group", "admins"), "Path": "/"})
		case graph.NodeRole:
			sc.roles = append(sc.roles, map[string]any{
				"RoleName": "victim-role", "Arn": arnOf("role", "victim-role"), "Path": "/",
				"AssumeRolePolicyDocument": trustFor(map[string]any{"Service": "ec2.amazonaws.com"}),
			})
		case graph.NodeService, graph.NodeExternalAccount, graph.NodeFederated, graph.NodeAnyPrincipal, graph.NodeTier0Sink:
			// Pair rules only target users, groups and roles.
		}
	case passRoleRule:
		role := map[string]any{
			"RoleName": "runtime", "Arn": arnOf("role", "runtime"), "Path": "/",
			"AssumeRolePolicyDocument": trustFor(map[string]any{"Service": x.service}),
		}
		if x.service == "ec2.amazonaws.com" {
			role["InstanceProfileList"] = []any{map[string]any{"InstanceProfileName": "runtime", "Arn": "arn:aws:iam::" + acct + ":instance-profile/runtime"}}
		}
		sc.roles = append(sc.roles, role)
	case updateCodeRule:
		sc.roles = append(sc.roles, map[string]any{
			"RoleName": "runtime", "Arn": arnOf("role", "runtime"), "Path": "/",
			"AssumeRolePolicyDocument": trustFor(map[string]any{"Service": x.service}),
			"InstanceProfileList":      []any{map[string]any{"InstanceProfileName": "runtime", "Arn": "arn:aws:iam::" + acct + ":instance-profile/runtime"}},
		})
		sc.resources = map[string]any{
			"lambda":    []any{map[string]any{"arn": "arn:aws:lambda:us-east-1:" + acct + ":function:job", "role": arnOf("role", "runtime")}},
			"ec2":       []any{map[string]any{"arn": "arn:aws:ec2:us-east-1:" + acct + ":instance/i-0123456789abcdef0", "instance_profile": "arn:aws:iam::" + acct + ":instance-profile/runtime", "ssm_managed": true}},
			"codebuild": []any{map[string]any{"arn": "arn:aws:codebuild:us-east-1:" + acct + ":project/build", "service_role": arnOf("role", "runtime")}},
		}
	case compositeRule:
		victim := map[string]any{"Path": "/"}
		var actorARNs []any
		for _, n := range actorNames {
			actorARNs = append(actorARNs, arnOf(kind, n))
		}
		if x.targetKind == graph.NodeRole {
			victim["RoleName"], victim["Arn"] = "victim-role", arnOf("role", "victim-role")
			trusted := map[string]any{"Service": "ec2.amazonaws.com"}
			if x.actAs[0] == graph.EdgeAssume {
				trusted = map[string]any{"AWS": actorARNs}
			}
			victim["AssumeRolePolicyDocument"] = trustFor(trusted)
			victim["AttachedManagedPolicies"] = []any{map[string]any{"PolicyName": "VictimPolicy", "PolicyArn": arnOf("policy", "VictimPolicy")}}
			sc.policies = append(sc.policies, managed("VictimPolicy", doc(statement([]string{"s3:GetObject"}))))
			sc.roles = append(sc.roles, victim)
		} else {
			victim["UserName"], victim["Arn"] = "victim", arnOf("user", "victim")
			sc.users = append(sc.users, victim)
		}
	case assumeRule:
		var actorARNs []any
		for _, n := range actorNames {
			actorARNs = append(actorARNs, arnOf(kind, n))
		}
		trust := trustFor(map[string]any{"AWS": actorARNs})
		if v.conditional {
			trust = doc(map[string]any{
				"Effect": "Allow", "Principal": map[string]any{"AWS": actorARNs}, "Action": "sts:AssumeRole",
				"Condition": map[string]any{"Bool": map[string]any{"aws:MultiFactorAuthPresent": "true"}},
			})
		}
		if v.noPolicy {
			trust = trustFor(map[string]any{"Service": "ec2.amazonaws.com"})
		}
		sc.roles = append(sc.roles, map[string]any{"RoleName": "target", "Arn": arnOf("role", "target"), "Path": "/", "AssumeRolePolicyDocument": trust})
	}
	return sc
}

// setupSelf gives self-escalation actors the policy or group they modify.
func setupSelf(sc *scenario, r selfRule, entity map[string]any, name string, v variant) {
	switch r.meta.RequiredActions[0] {
	case "iam:CreatePolicyVersion":
		entity["AttachedManagedPolicies"] = []any{map[string]any{"PolicyName": "AppPolicy-" + name, "PolicyArn": arnOf("policy", "AppPolicy-"+name)}}
		sc.policies = append(sc.policies, managed("AppPolicy-"+name, doc(statement([]string{"s3:GetObject"}))))
	case "iam:AttachGroupPolicy", "iam:PutGroupPolicy":
		entity["GroupList"] = []any{"devs"}
		if len(sc.groups) == 0 {
			sc.groups = append(sc.groups, map[string]any{"GroupName": "devs", "Arn": arnOf("group", "devs"), "Path": "/"})
		}
	}
	_ = v
}

func managed(name string, d map[string]any) map[string]any {
	return map[string]any{
		"PolicyName": name, "Arn": arnOf("policy", name), "Path": "/", "DefaultVersionId": "v1",
		"PolicyVersionList": []any{map[string]any{"VersionId": "v1", "IsDefaultVersion": true, "Document": d}},
	}
}

func (sc scenario) envelope() map[string]any {
	acctDoc := map[string]any{
		"account_id": acct,
		"authorization_details": map[string]any{
			"UserDetailList": orEmpty(sc.users), "GroupDetailList": orEmpty(sc.groups),
			"RoleDetailList": orEmpty(sc.roles), "Policies": orEmpty(sc.policies),
		},
	}
	if sc.resources != nil {
		acctDoc["resources"] = sc.resources
	}
	env := map[string]any{"escalint_snapshot": "1", "collected_at": "2026-10-23T00:00:00Z", "partition": "aws", "accounts": []any{acctDoc}}
	if len(sc.scpDeny) > 0 {
		env["organization"] = map[string]any{
			"id": "o-exampleorg1", "management_account_id": "222222222222",
			"tree": []any{
				map[string]any{"id": "r-ab12", "type": "ROOT", "parent": nil},
				map[string]any{"id": acct, "type": "ACCOUNT", "parent": "r-ab12"},
			},
			"policies": []any{
				map[string]any{"id": "p-FullAWSAccess", "type": "SERVICE_CONTROL_POLICY", "name": "FullAWSAccess", "document": doc(statement([]string{"*"})), "targets": []any{"r-ab12", acct}},
				map[string]any{
					"id": "p-deny", "type": "SERVICE_CONTROL_POLICY", "name": "Deny", "targets": []any{acct},
					"document": doc(map[string]any{"Effect": "Deny", "Action": sc.scpDeny, "Resource": "*"}),
				},
			},
		}
	}
	return env
}

func orEmpty(list []map[string]any) []any {
	out := make([]any, 0, len(list))
	for _, m := range list {
		out = append(out, m)
	}
	return out
}

// runAll loads a snapshot, builds the graph and applies every rule in pass
// order, like the engine does.
func runAll(t *testing.T, data []byte) *graph.Graph {
	t.Helper()
	snap, err := snapshot.Load(strings.NewReader(string(data)), snapshot.Options{})
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	g, env := graph.Build(snap, graph.Options{})
	cat, err := catalog.Default()
	if err != nil {
		t.Fatal(err)
	}
	ctx := &Context{Graph: g, Env: env, Snap: snap, Catalog: cat}
	for _, pass := range []Pass{PassPrimitive, PassComposite} {
		for _, r := range All() {
			if r.Pass() == pass {
				r.Apply(ctx)
			}
		}
	}
	return g
}

func edgesOf(g *graph.Graph, ruleID string) []*graph.Edge {
	var out []*graph.Edge
	for _, e := range g.Edges() {
		for _, id := range e.RuleIDs {
			if id == ruleID && !e.Latent {
				out = append(out, e)
			}
		}
	}
	return out
}

func TestRulesScenarios(t *testing.T) {
	for _, r := range All() {
		m := r.Meta()
		if m.EdgeKind == "" {
			continue // trust and parse rules report findings, tested separately
		}
		for _, v := range variants {
			t.Run(m.ID+"/"+v.name, func(t *testing.T) {
				data, err := json.MarshalIndent(build(r, v).envelope(), "", " ")
				if err != nil {
					t.Fatal(err)
				}
				data = append(data, '\n')
				if v.writeFixture != "" {
					checkFixture(t, filepath.Join("testdata", m.ID, v.writeFixture, "snapshot.json"), data)
				}
				// Edges between the attackers themselves are real (users can
				// take over each other) but not what the scenario counts.
				gr := runAll(t, data)
				var edges []*graph.Edge
				for _, e := range edgesOf(gr, m.ID) {
					if !strings.HasPrefix(gr.Node(e.To).Name, "attacker") {
						edges = append(edges, e)
					}
				}
				if len(edges) != v.wantEdges {
					t.Fatalf("%d edges for %s, want %d", len(edges), m.ID, v.wantEdges)
				}
				for _, e := range edges {
					if e.Kind != m.EdgeKind {
						t.Errorf("edge kind %s, want %s", e.Kind, m.EdgeKind)
					}
					if v.wantStatus != "" && e.Status != v.wantStatus {
						t.Errorf("status %s, want %s", e.Status, v.wantStatus)
					}
					if len(e.Evidence) == 0 && m.EdgeKind != graph.EdgeAssume {
						t.Error("edge without evidence")
					}
				}
			})
		}
	}
}

// checkFixture compares a generated fixture with testdata (or rewrites it
// with -update), so fixtures on disk always match the scenarios.
func checkFixture(t *testing.T, path string, data []byte) {
	t.Helper()
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing fixture %s (run go test ./internal/rules -update): %v", path, err)
	}
	if string(got) != string(data) {
		t.Fatalf("fixture %s is stale (run go test ./internal/rules -update)", path)
	}
}

// Security review (Phase 19): a permissions boundary that allows the
// self-escalation action but not administrator actions caps the result, so
// the edge to Tier 0 is conditional with the reason; a boundary that allows
// everything keeps it allowed.
func TestSelfEscalationCappedByBoundary(t *testing.T) {
	for _, r := range All() {
		self, ok := r.(selfRule)
		if !ok {
			continue
		}
		for _, tc := range []struct {
			name     string
			boundary []string
			want     graph.Status
		}{
			{"narrow boundary", self.meta.RequiredActions, graph.StatusConditional},
			{"admin boundary", []string{"*"}, graph.StatusAllowed},
		} {
			t.Run(self.meta.ID+"/"+tc.name, func(t *testing.T) {
				sc := build(r, variant{name: "positive"})
				all := slices.Concat(sc.users, sc.roles)
				for _, e := range all {
					if n, _ := e["UserName"].(string); n == "attacker" {
						e["PermissionsBoundary"] = map[string]any{"PermissionsBoundaryType": "Policy", "PermissionsBoundaryArn": arnOf("policy", "Cap")}
					}
					if n, _ := e["RoleName"].(string); n == "attacker" {
						e["PermissionsBoundary"] = map[string]any{"PermissionsBoundaryType": "Policy", "PermissionsBoundaryArn": arnOf("policy", "Cap")}
					}
				}
				sc.policies = append(sc.policies, managed("Cap", doc(statement(tc.boundary))))
				data, err := json.Marshal(sc.envelope())
				if err != nil {
					t.Fatal(err)
				}
				edges := edgesOf(runAll(t, data), self.meta.ID)
				if len(edges) != 1 {
					t.Fatalf("edges = %d", len(edges))
				}
				if edges[0].Status != tc.want {
					t.Errorf("status = %s, want %s", edges[0].Status, tc.want)
				}
				if tc.want == graph.StatusConditional && (len(edges[0].PrerequisitesUnverified) != 1 || !strings.Contains(edges[0].PrerequisitesUnverified[0], "permissions boundary")) {
					t.Errorf("prerequisites = %v", edges[0].PrerequisitesUnverified)
				}
			})
		}
	}
}
