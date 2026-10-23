package catalog

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/brennocm/escalint/internal/match"
)

func mustDefault(t testing.TB) *Catalog {
	t.Helper()
	c, err := Default()
	if err != nil {
		t.Fatalf("Default() error = %v", err)
	}
	return c
}

func TestDefaultLoadsEmbeddedCatalog(t *testing.T) {
	c := mustDefault(t)
	if c.Len() < 10000 || len(c.Services()) < 300 {
		t.Fatalf("catalog looks truncated: %d actions, %d services", c.Len(), len(c.Services()))
	}
	if c.Generated == "" || !strings.HasPrefix(c.Source, "https://servicereference.") {
		t.Errorf("metadata missing: generated=%q source=%q", c.Generated, c.Source)
	}
	again := mustDefault(t)
	if again != c {
		t.Error("Default() must decode once and share the result")
	}
}

func TestLookup(t *testing.T) {
	c := mustDefault(t)
	tests := []struct {
		in     string
		want   string
		access AccessLevel
	}{
		// AWS annotates PassRole and CreateAccessKey as Write, not permission
		// management (verified in the service reference, 2026-10-23).
		{"iam:PassRole", "iam:PassRole", Write},
		{"IAM:passrole", "iam:PassRole", Write},
		{"iam:CreateAccessKey", "iam:CreateAccessKey", Write},
		{"iam:PutRolePolicy", "iam:PutRolePolicy", PermissionManagement},
		{"s3:GetObject", "s3:GetObject", Read},
		{"s3:ListBucket", "s3:ListBucket", List},
		{"lambda:CreateFunction", "lambda:CreateFunction", Write},
		{"iam:TagRole", "iam:TagRole", Tagging},
		{"sts:AssumeRole", "sts:AssumeRole", ""},
	}
	for _, tc := range tests {
		a, ok := c.Lookup(tc.in)
		if !ok || a.String() != tc.want {
			t.Errorf("Lookup(%q) = %v, %v", tc.in, a, ok)
			continue
		}
		if tc.access != "" && a.Access != tc.access {
			t.Errorf("Lookup(%q).Access = %q, want %q", tc.in, a.Access, tc.access)
		}
	}
	for _, missing := range []string{"iam:PassRol", "nope:Action", "iam", ""} {
		if _, ok := c.Lookup(missing); ok {
			t.Errorf("Lookup(%q) found an action", missing)
		}
	}
}

func TestExpand(t *testing.T) {
	c := mustDefault(t)
	iam, _ := c.Service("iam")
	if got := c.Expand("iam:*"); len(got) != len(iam.Actions) {
		t.Errorf("Expand(iam:*) = %d actions, want %d", len(got), len(iam.Actions))
	}
	if got := c.Expand("*"); len(got) != c.Len() {
		t.Errorf("Expand(*) = %d actions, want %d", len(got), c.Len())
	}
	names := func(as []Action) map[string]bool {
		m := map[string]bool{}
		for _, a := range as {
			m[a.String()] = true
		}
		return m
	}
	policyActions := names(c.Expand("iam:*Policy*"))
	for _, want := range []string{"iam:PutRolePolicy", "iam:AttachUserPolicy", "iam:CreatePolicyVersion"} {
		if !policyActions[want] {
			t.Errorf("Expand(iam:*Policy*) misses %s", want)
		}
	}
	if policyActions["iam:PassRole"] {
		t.Error("Expand(iam:*Policy*) includes iam:PassRole")
	}
	if got := c.Expand("IAM:PASSROLE"); len(got) != 1 || got[0].String() != "iam:PassRole" {
		t.Errorf("Expand(IAM:PASSROLE) = %v", got)
	}
	if got := c.Expand("*:PassRole"); len(names(got)) == 0 || !names(got)["iam:PassRole"] {
		t.Errorf("Expand(*:PassRole) = %v", got)
	}
	for _, none := range []string{"iam", "nope:*", "iam:NoSuchAction"} {
		if got := c.Expand(none); len(got) != 0 {
			t.Errorf("Expand(%q) = %v, want none", none, got)
		}
	}
}

// Properties from the Phase 3 specification, checked with random catalog
// actions and random patterns derived from them.
func TestExpandProperties(t *testing.T) {
	c := mustDefault(t)
	services := c.Services()
	rapid.Check(t, func(t *rapid.T) {
		svc := rapid.SampledFrom(services).Draw(t, "service")
		action := rapid.SampledFrom(svc.Actions).Draw(t, "action")

		// An exact action name, in any case, expands to itself only.
		name := action.String()
		if rapid.Bool().Draw(t, "upper") {
			name = strings.ToUpper(name)
		}
		got := c.Expand(name)
		if len(got) != 1 || got[0].String() != action.String() {
			t.Fatalf("Expand(%q) = %v, want [%s]", name, got, action)
		}

		// "service:*" covers every action of the service.
		all := c.Expand(svc.Prefix + ":*")
		if len(all) != len(svc.Actions) {
			t.Fatalf("Expand(%s:*) = %d, want %d", svc.Prefix, len(all), len(svc.Actions))
		}

		// A prefix pattern: the expansion is a subset of the catalog, every
		// element matches the pattern, and the source action is included.
		cut := rapid.IntRange(0, len(action.Name)).Draw(t, "cut")
		pattern := svc.Prefix + ":" + action.Name[:cut] + "*"
		found := false
		for _, a := range c.Expand(pattern) {
			if _, ok := c.Lookup(a.String()); !ok {
				t.Fatalf("Expand(%q) returned %s, which is not in the catalog", pattern, a)
			}
			if !match.Action(pattern, a.String()) {
				t.Fatalf("Expand(%q) returned %s, which does not match", pattern, a)
			}
			found = found || a.String() == action.String()
		}
		if !found {
			t.Fatalf("Expand(%q) misses %s", pattern, action)
		}
	})
}

// Every action named in the approved v1 rule catalog (docs/research.md §7)
// must exist. This moves to the rule registry test in Phase 6.
func TestRuleCatalogActionsExist(t *testing.T) {
	c := mustDefault(t)
	actions := []string{
		"iam:CreatePolicyVersion", "iam:PutRolePolicy", "iam:PutUserPolicy", "iam:AttachUserPolicy",
		"iam:AttachRolePolicy", "iam:AttachGroupPolicy", "iam:PutGroupPolicy", "iam:AddUserToGroup",
		"iam:CreateAccessKey", "iam:DeleteAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile",
		"iam:UpdateAssumeRolePolicy", "sts:AssumeRole", "sts:AssumeRoleWithWebIdentity", "sts:AssumeRoleWithSAML",
		"iam:PassRole", "ec2:RunInstances", "lambda:CreateFunction", "lambda:InvokeFunction",
		"cloudformation:CreateStack", "codebuild:CreateProject", "codebuild:StartBuild", "glue:CreateJob",
		"glue:StartJobRun", "ecs:RegisterTaskDefinition", "ecs:RunTask", "ecs:CreateCluster",
		"sagemaker:CreateNotebookInstance", "lambda:UpdateFunctionCode", "ssm:SendCommand",
		"iam:DeleteRolePermissionsBoundary", "iam:DeleteUserPermissionsBoundary",
		"s3:GetObject", "kms:Decrypt", "secretsmanager:GetSecretValue",
	}
	for _, a := range actions {
		if _, ok := c.Lookup(a); !ok {
			t.Errorf("rule catalog action %s is not in the AWS catalog", a)
		}
	}
}

func encodeFile(t *testing.T, f File) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(f); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf
}

func TestDecodeErrors(t *testing.T) {
	if _, err := Decode(strings.NewReader("not gzip")); err == nil {
		t.Error("Decode(non-gzip) error = nil")
	}
	var garbage bytes.Buffer
	zw := gzip.NewWriter(&garbage)
	_, _ = zw.Write([]byte("{"))
	_ = zw.Close()
	if _, err := Decode(&garbage); err == nil {
		t.Error("Decode(bad json) error = nil")
	}
	tests := map[string]File{
		"version":           {FormatVersion: 99},
		"duplicate service": {FormatVersion: FormatVersion, Services: []FileService{{Prefix: "a"}, {Prefix: "a"}}},
		"duplicate action": {FormatVersion: FormatVersion, Services: []FileService{{Prefix: "a", Actions: []FileAction{
			{Name: "X", Access: Read}, {Name: "x", Access: Read},
		}}}},
	}
	for name, f := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(encodeFile(t, f)); err == nil {
				t.Errorf("Decode(%s) error = nil", name)
			}
		})
	}
}

func TestAccessFromAnnotations(t *testing.T) {
	tests := []struct {
		pm, tag, write, list bool
		want                 AccessLevel
	}{
		{true, true, true, true, PermissionManagement},
		{false, true, true, false, Tagging},
		{false, false, true, true, Write},
		{false, false, false, true, List},
		{false, false, false, false, Read},
	}
	for _, tc := range tests {
		if got := AccessFromAnnotations(tc.pm, tc.tag, tc.write, tc.list); got != tc.want {
			t.Errorf("AccessFromAnnotations(%v,%v,%v,%v) = %q, want %q", tc.pm, tc.tag, tc.write, tc.list, got, tc.want)
		}
	}
}

func BenchmarkDecode(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := Decode(bytes.NewReader(embedded)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkExpandService(b *testing.B) {
	c := mustDefault(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Expand("iam:Put*")
	}
}

func BenchmarkExpandAll(b *testing.B) {
	c := mustDefault(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Expand("*:Get*")
	}
}
