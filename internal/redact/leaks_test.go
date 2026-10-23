package redact

import (
	"strings"
	"testing"

	"github.com/brennocm/escalint/internal/contract"
)

// The leaks found in the Phase 19 security review: identifiers that reach
// the output through condition keys, GitHub subjects, names of missing
// groups and file paths, none of which are graph nodes.
const leakySnapshot = `{
  "UserDetailList": [{
    "Path": "/", "UserName": "u1", "UserId": "AIDAAAAAAAAAAAAAAAAAA",
    "Arn": "arn:aws:iam::111111111111:user/u1",
    "GroupList": ["HiddenGroupZeta"],
    "UserPolicyList": [{"PolicyName": "p", "PolicyDocument": {"Version": "2012-10-17", "Statement": [
      {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*",
       "Condition": {"StringEquals": {"aws:PrincipalTag/ProjectNightingale": "yes"}}}]}}],
    "AttachedManagedPolicies": [], "Tags": []
  }],
  "GroupDetailList": [],
  "RoleDetailList": [
    {"Path": "/", "RoleName": "ci", "RoleId": "AROAAAAAAAAAAAAAAAAAA", "Arn": "arn:aws:iam::111111111111:role/ci",
     "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
       "Principal": {"Federated": "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"},
       "Action": "sts:AssumeRoleWithWebIdentity",
       "Condition": {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
                     "StringLike": {"token.actions.githubusercontent.com:sub": "repo:acmesecretorg/*"}}}]},
     "RolePolicyList": [{"PolicyName": "admin", "PolicyDocument": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}],
     "AttachedManagedPolicies": [], "InstanceProfileList": [], "Tags": []},
    {"Path": "/", "RoleName": "eks", "RoleId": "AROABBBBBBBBBBBBBBBBB", "Arn": "arn:aws:iam::111111111111:role/eks",
     "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
       "Principal": {"Federated": "arn:aws:iam::111111111111:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/CLUSTERSECRET42"},
       "Action": "sts:AssumeRoleWithWebIdentity",
       "Condition": {"StringEquals": {"oidc.eks.us-east-1.amazonaws.com/id/CLUSTERSECRET42:aud": "sts.amazonaws.com"}}}]},
     "RolePolicyList": [], "AttachedManagedPolicies": [], "InstanceProfileList": [], "Tags": []},
    {"Path": "/", "RoleName": "ops", "RoleId": "AROACCCCCCCCCCCCCCCCC", "Arn": "arn:aws:iam::111111111111:role/ops",
     "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
       "Principal": {"AWS": "arn:aws:iam::111111111111:root"}, "Action": "sts:AssumeRole"}]},
     "RolePolicyList": [{"PolicyName": "admin", "PolicyDocument": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}],
     "AttachedManagedPolicies": [], "InstanceProfileList": [], "Tags": []}
  ],
  "Policies": []
}`

func TestNoLeaksThroughConditionsSubjectsAndDiagnostics(t *testing.T) {
	a := analysisOf(t, []byte(leakySnapshot))
	before, err := contract.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	secrets := []string{"projectnightingale", "ProjectNightingale", "acmesecretorg", "HiddenGroupZeta", "CLUSTERSECRET42", "clustersecret42"}
	seen := 0
	for _, s := range secrets {
		if strings.Contains(string(before), s) {
			seen++
		}
	}
	if seen < 5 {
		t.Fatalf("the fixture no longer exercises the leaks (%d of %d secrets in the unredacted output)", seen, len(secrets))
	}
	r := fixed(t)
	r.Analysis(a)
	after, err := contract.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range secrets {
		if strings.Contains(string(after), s) {
			t.Errorf("%q survives redaction", s)
		}
	}
	// The point of each finding stays readable.
	for _, keep := range []string{"repo:github-", "/*", "aws:principaltag/tag-", ":aud"} {
		if !strings.Contains(string(after), keep) {
			t.Errorf("%q lost: the redacted output no longer explains the finding", keep)
		}
	}
}

func TestConditionKey(t *testing.T) {
	r := fixed(t)
	for _, k := range []string{"aws:sourceip", "sts:externalid", "token.actions.githubusercontent.com:sub", "aws:principalorgid"} {
		if got := r.ConditionKey(k); got != k {
			t.Errorf("ConditionKey(%q) = %q, want unchanged", k, got)
		}
	}
	for k, want := range map[string]string{
		"aws:principaltag/team":                     "aws:principaltag/tag-",
		"iam:resourcetag/owner":                     "iam:resourcetag/tag-",
		"oidc.eks.eu-west-1.amazonaws.com/id/X:sub": "federated-",
	} {
		got := r.ConditionKey(k)
		if !strings.HasPrefix(got, want) || got == k {
			t.Errorf("ConditionKey(%q) = %q, want prefix %q", k, got, want)
		}
	}
	if got := r.conditionKeysIn(`Statement[0].Condition.StringEquals["aws:principaltag/team"]`); strings.Contains(got, "team") {
		t.Errorf("path keeps the tag: %s", got)
	}
}

func TestGitHubSubjectsAndQuoted(t *testing.T) {
	r := fixed(t)
	got := r.GitHubSubjects("accepts broad subjects: repo:acme/*, repo:acme/app:environment:prod, repo:*")
	for _, leak := range []string{"acme", "app:", "prod"} {
		if strings.Contains(got, leak) {
			t.Errorf("%q survives in %q", leak, got)
		}
	}
	if !strings.Contains(got, "/*,") || !strings.Contains(got, "repo:*") || !strings.Contains(got, ":environment:github-") {
		t.Errorf("shape lost: %q", got)
	}
	if got := r.GitHubSubjects("prepo:x/y"); got != "prepo:x/y" {
		t.Errorf("matched inside a word: %q", got)
	}
	q := r.quoted(`member of group "secret-team", default version "v3", "unterminated`)
	if strings.Contains(q, "secret-team") || !strings.Contains(q, `"v3"`) || !strings.HasSuffix(q, `"unterminated`) {
		t.Errorf("quoted = %q", q)
	}
}

func TestFile(t *testing.T) {
	r := fixed(t)
	for in, want := range map[string]string{"": "", "/tmp/x/.escalint.yaml": ".escalint.yaml", "snapshot.json": "snapshot.json", `C:\acme\analysis.json`: "analysis.json"} {
		if got := r.File(in); got != want {
			t.Errorf("File(%q) = %q, want %q", in, got, want)
		}
	}
	got := r.File("/home/alice/acme-prod/acme-prod-snapshot.json")
	if strings.Contains(got, "acme") || strings.Contains(got, "alice") || !strings.HasSuffix(got, ".json") {
		t.Errorf("File = %q", got)
	}
}
