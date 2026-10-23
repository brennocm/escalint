package rules

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/brennocm/escalint/internal/graph"
	"github.com/brennocm/escalint/internal/snapshot"
)

const ghProvider = "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"

// trustSnapshot is one role with the given trust statement (and an admin
// policy, so trust findings can sit on paths).
func trustSnapshot(t *testing.T, statement map[string]any) *Context {
	t.Helper()
	doc := map[string]any{"Version": "2012-10-17", "Statement": []any{statement}}
	authz := map[string]any{
		"UserDetailList": []any{}, "GroupDetailList": []any{}, "Policies": []any{},
		"RoleDetailList": []any{map[string]any{
			"Path": "/", "RoleName": "target", "RoleId": "AROATARGET", "Arn": "arn:aws:iam::111111111111:role/target",
			"AssumeRolePolicyDocument": doc, "RolePolicyList": []any{}, "AttachedManagedPolicies": []any{},
		}},
	}
	data, err := json.Marshal(authz)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := snapshot.Load(strings.NewReader(string(data)), snapshot.Options{})
	if err != nil {
		t.Fatal(err)
	}
	g, env := graph.Build(snap, graph.Options{})
	return &Context{Graph: g, Env: env, Snap: snap}
}

func stmt(principal map[string]any, action string, cond map[string]any) map[string]any {
	s := map[string]any{"Effect": "Allow", "Principal": principal, "Action": action}
	if cond != nil {
		s["Condition"] = cond
	}
	return s
}

func eq(k, v string) map[string]any { return map[string]any{"StringEquals": map[string]any{k: v}} }

func TestTrustRules(t *testing.T) {
	ghAud := map[string]any{"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}
	withSub := func(op, sub string) map[string]any {
		c := map[string]any{"StringEquals": ghAud}
		if op == "StringEquals" {
			c = map[string]any{"StringEquals": map[string]any{"token.actions.githubusercontent.com:aud": "sts.amazonaws.com", "token.actions.githubusercontent.com:sub": sub}}
		} else {
			c[op] = map[string]any{"token.actions.githubusercontent.com:sub": sub}
		}
		return c
	}
	cases := []struct {
		name   string
		rule   Rule
		st     map[string]any
		config Config
		want   int
		substr string
	}{
		{"any principal", elTR001(), stmt(map[string]any{"AWS": "*"}, "sts:AssumeRole", nil), Config{}, 1, "any AWS principal"},
		{"star principal", elTR001(), map[string]any{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}, Config{}, 1, ""},
		{"org restricted", elTR001(), stmt(map[string]any{"AWS": "*"}, "sts:AssumeRole", eq("aws:PrincipalOrgID", "o-exampleorg1")), Config{}, 0, ""},
		{"source ip only", elTR001(), stmt(map[string]any{"AWS": "*"}, "sts:AssumeRole", map[string]any{"IpAddress": map[string]any{"aws:SourceIp": "203.0.113.0/24"}}), Config{}, 1, "conditional"},
		{"github no sub", elTR002(), stmt(map[string]any{"Federated": ghProvider}, "sts:AssumeRoleWithWebIdentity", map[string]any{"StringEquals": ghAud}), Config{}, 1, "any repository"},
		{"github with sub", elTR002(), stmt(map[string]any{"Federated": ghProvider}, "sts:AssumeRoleWithWebIdentity", withSub("StringEquals", "repo:example-org/app:ref:refs/heads/main")), Config{}, 0, ""},
		{"github broad sub", elTR003(), stmt(map[string]any{"Federated": ghProvider}, "sts:AssumeRoleWithWebIdentity", withSub("StringLike", "repo:example-org/*")), Config{}, 1, "repo:example-org/*"},
		{"github pinned sub", elTR003(), stmt(map[string]any{"Federated": ghProvider}, "sts:AssumeRoleWithWebIdentity", withSub("StringEquals", "repo:example-org/app:environment:prod")), Config{}, 0, ""},
		{"github no sub is TR-002", elTR003(), stmt(map[string]any{"Federated": ghProvider}, "sts:AssumeRoleWithWebIdentity", map[string]any{"StringEquals": ghAud}), Config{}, 0, ""},
		{"external account", elTR004(), stmt(map[string]any{"AWS": "arn:aws:iam::999999999999:root"}, "sts:AssumeRole", nil), Config{}, 1, "999999999999"},
		{"external account id form", elTR004(), stmt(map[string]any{"AWS": "999999999999"}, "sts:AssumeRole", nil), Config{}, 1, ""},
		{"trusted account", elTR004(), stmt(map[string]any{"AWS": "arn:aws:iam::999999999999:root"}, "sts:AssumeRole", nil), Config{TrustedAccounts: []string{"999999999999"}}, 0, ""},
		{"vendor is not TR-004", elTR004(), stmt(map[string]any{"AWS": "arn:aws:iam::999999999999:root"}, "sts:AssumeRole", nil), Config{ThirdPartyAccounts: []string{"999999999999"}}, 0, ""},
		{"vendor without external id", elTR005(), stmt(map[string]any{"AWS": "arn:aws:iam::999999999999:root"}, "sts:AssumeRole", nil), Config{ThirdPartyAccounts: []string{"999999999999"}}, 1, "confused deputy"},
		{"vendor with external id", elTR005(), stmt(map[string]any{"AWS": "arn:aws:iam::999999999999:root"}, "sts:AssumeRole", eq("sts:ExternalId", "abc")), Config{ThirdPartyAccounts: []string{"999999999999"}}, 0, ""},
		{"unlisted is not TR-005", elTR005(), stmt(map[string]any{"AWS": "arn:aws:iam::999999999999:root"}, "sts:AssumeRole", nil), Config{}, 0, ""},
		{"generic oidc", elTR006(), stmt(map[string]any{"Federated": "arn:aws:iam::111111111111:oidc-provider/oidc.example.com"}, "sts:AssumeRoleWithWebIdentity", nil), Config{}, 1, "oidc.example.com:aud"},
		{"generic oidc with aud", elTR006(), stmt(map[string]any{"Federated": "arn:aws:iam::111111111111:oidc-provider/oidc.example.com"}, "sts:AssumeRoleWithWebIdentity", eq("oidc.example.com:aud", "app")), Config{}, 0, ""},
		{"saml", elTR006(), stmt(map[string]any{"Federated": "arn:aws:iam::111111111111:saml-provider/corp"}, "sts:AssumeRoleWithSAML", nil), Config{}, 1, "SAML:aud"},
		{"saml with aud", elTR006(), stmt(map[string]any{"Federated": "arn:aws:iam::111111111111:saml-provider/corp"}, "sts:AssumeRoleWithSAML", eq("SAML:aud", "https://signin.aws.amazon.com/saml")), Config{}, 0, ""},
		{"github is not TR-006", elTR006(), stmt(map[string]any{"Federated": ghProvider}, "sts:AssumeRoleWithWebIdentity", nil), Config{}, 0, ""},
		{"service trust", elTR001(), stmt(map[string]any{"Service": "lambda.amazonaws.com"}, "sts:AssumeRole", nil), Config{}, 0, ""},
		{"deny wins", elTR001(), map[string]any{"Effect": "Deny", "Principal": "*", "Action": "sts:AssumeRole"}, Config{}, 0, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := trustSnapshot(t, c.st)
			ctx.Config = c.config
			got := c.rule.Apply(ctx)
			if len(got) != c.want {
				t.Fatalf("%d findings, want %d: %+v", len(got), c.want, got)
			}
			for _, f := range got {
				if f.NodeID != graph.NodeID("arn:aws:iam::111111111111:role/target") || f.EdgeID == "" || f.Location.Policy != "trust:arn:aws:iam::111111111111:role/target" || f.Location.Statement != 0 {
					t.Errorf("finding = %+v", f)
				}
				if !strings.Contains(f.Message, c.substr) {
					t.Errorf("message %q lacks %q", f.Message, c.substr)
				}
			}
		})
	}
}

func TestBroadGitHubSubject(t *testing.T) {
	broad := []string{"*", "*:*", "repo:*", "repo:org/*", "repo:*/app:ref:refs/heads/main", "repo:org/app", "repo:org/app:*", "repo:org", "repo:org/"}
	narrow := []string{"repo:org/app:ref:refs/heads/main", "repo:org/app:environment:prod", "repo:org/app:pull_request", "repo:org/app:ref:refs/tags/v*"}
	for _, s := range broad {
		if !BroadGitHubSubject(s) {
			t.Errorf("%q should be broad", s)
		}
	}
	for _, s := range narrow {
		if BroadGitHubSubject(s) {
			t.Errorf("%q should be narrow", s)
		}
	}
}
