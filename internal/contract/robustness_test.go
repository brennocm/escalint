package contract

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/brennocm/escalint/internal/engine"
	"github.com/brennocm/escalint/internal/snapshot"
)

// Robustness of the whole pipeline (load, engine, contract) on inputs at
// the edges of what AWS allows and on hostile identifiers: every case must
// finish, produce valid UTF-8 JSON that matches the schema, and never panic.

const robustAccount = "111111111111"

func roleARN(name string) string { return "arn:aws:iam::" + robustAccount + ":role/" + name }

func assumeDoc(arns ...string) map[string]any {
	return map[string]any{"Version": "2012-10-17", "Statement": []any{
		map[string]any{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": arns},
	}}
}

func trustDoc(principal string) map[string]any {
	return map[string]any{"Version": "2012-10-17", "Statement": []any{
		map[string]any{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": map[string]any{"AWS": principal}},
	}}
}

func role(name, trusted string, inline ...map[string]any) map[string]any {
	var list []any
	for i, d := range inline {
		list = append(list, map[string]any{"PolicyName": fmt.Sprintf("p%d", i), "PolicyDocument": d})
	}
	return map[string]any{
		"Arn": roleARN(name), "RoleName": name, "RoleId": "AROA" + strings.ToUpper(fmt.Sprintf("%016x", len(name))), "Path": "/",
		"AssumeRolePolicyDocument": trustDoc(trusted), "RolePolicyList": list, "AttachedManagedPolicies": []any{},
	}
}

func details(roles, users, policies []any) map[string]any {
	return map[string]any{"UserDetailList": users, "GroupDetailList": []any{}, "RoleDetailList": roles, "Policies": policies}
}

func runPipeline(t *testing.T, raw []byte) (*engine.Result, []byte) {
	t.Helper()
	snap, err := snapshot.Load(strings.NewReader(string(raw)), snapshot.Options{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := engine.Run(snap, engine.Options{})
	if err != nil {
		t.Fatal(err)
	}
	a, err := Build(res, Meta{Deterministic: true})
	if err != nil {
		t.Fatal(err)
	}
	data, err := Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if !utf8.Valid(data) || !json.Valid(data) {
		t.Fatal("output is not valid UTF-8 JSON")
	}
	validate(t, compileSchema(t), data)
	return res, data
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A ring of roles, each able to assume the next: one strongly connected
// component that must be reported as a cycle without exploding the path
// enumeration.
func TestRobustAssumeRoleRing(t *testing.T) {
	const n = 300
	var roles []any
	for i := range n {
		next, prev := fmt.Sprintf("r%03d", (i+1)%n), fmt.Sprintf("r%03d", (i+n-1)%n)
		roles = append(roles, role(fmt.Sprintf("r%03d", i), roleARN(prev), assumeDoc(roleARN(next))))
	}
	res, _ := runPipeline(t, mustJSON(t, details(roles, []any{}, []any{})))
	if len(res.Cycles) != 1 || len(res.Cycles[0]) != n {
		t.Fatalf("cycles = %d (first of %d nodes), want one of %d", len(res.Cycles), len(res.Cycles[0]), n)
	}
}

// Managed policies are limited to 6,144 characters and inline role policies
// to 10,240 in aggregate (IAM and AWS STS quotas); documents at those sizes
// load without diagnostics.
func TestRobustPoliciesAtAWSSizeLimits(t *testing.T) {
	fill := func(limit int) map[string]any {
		var stmts []any
		for i := 0; ; i++ {
			s := map[string]any{"Effect": "Allow", "Action": "s3:GetObject", "Resource": fmt.Sprintf("arn:aws:s3:::bucket-%05d/*", i)}
			doc := map[string]any{"Version": "2012-10-17", "Statement": append(stmts, s)}
			if len(mustJSON(t, doc)) > limit {
				return map[string]any{"Version": "2012-10-17", "Statement": stmts}
			}
			stmts = append(stmts, s)
		}
	}
	managed := map[string]any{
		"Arn": "arn:aws:iam::" + robustAccount + ":policy/big", "PolicyName": "big", "DefaultVersionId": "v1", "Path": "/",
		"PolicyVersionList": []any{map[string]any{"VersionId": "v1", "IsDefaultVersion": true, "Document": fill(6144)}},
	}
	r := role("big", "arn:aws:iam::"+robustAccount+":root", fill(10240))
	r["AttachedManagedPolicies"] = []any{map[string]any{"PolicyName": "big", "PolicyArn": "arn:aws:iam::" + robustAccount + ":policy/big"}}
	res, _ := runPipeline(t, mustJSON(t, details([]any{r}, []any{}, []any{managed})))
	if len(res.Snapshot.Diagnostics) != 0 {
		t.Errorf("diagnostics = %+v", res.Snapshot.Diagnostics)
	}
}

// Identifiers can carry bidirectional overrides, zero-width and combining
// characters, NUL, emoji and 64 KB strings: they pass through intact and
// still produce findings.
func TestRobustHostileIdentifiers(t *testing.T) {
	weird := []string{"\u202eevil\u202c", "zero\u200bwidth", "e\u0301\u0301\u0301", "nul\x00byte", "\U0001F525", strings.Repeat("A", 64<<10)}
	var users []any
	for i, w := range weird {
		users = append(users, map[string]any{
			"Arn":      fmt.Sprintf("arn:aws:iam::%s:user/u%d", robustAccount, i),
			"UserName": fmt.Sprintf("u%d", i), "UserId": fmt.Sprintf("AIDA%016d", i), "Path": "/",
			"Tags":                    []any{map[string]any{"Key": "owner", "Value": w}},
			"UserPolicyList":          []any{map[string]any{"PolicyName": "p", "PolicyDocument": map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Sid": "", "Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": "*"}}}}},
			"AttachedManagedPolicies": []any{}, "GroupList": []any{},
		})
	}
	res, data := runPipeline(t, mustJSON(t, details([]any{}, users, []any{})))
	if len(res.Findings) == 0 {
		t.Error("no findings")
	}
	if !strings.Contains(string(data), strings.Repeat("A", 64<<10)) {
		t.Error("long tag value was truncated")
	}
}

// Invalid UTF-8 inside a string is either rejected or replaced; it never
// reaches the output as invalid bytes.
func TestRobustInvalidUTF8(t *testing.T) {
	raw := []byte(`{"UserDetailList":[{"Arn":"arn:aws:iam::111111111111:user/u","UserName":"u","UserId":"AIDA0","Path":"/","Tags":[{"Key":"k","Value":"bad` + "\xff\xfe" + `"}]}],"GroupDetailList":[],"RoleDetailList":[],"Policies":[]}`)
	snap, err := snapshot.Load(strings.NewReader(string(raw)), snapshot.Options{})
	if err != nil {
		return // rejected: fine
	}
	res, err := engine.Run(snap, engine.Options{})
	if err != nil {
		t.Fatal(err)
	}
	a, err := Build(res, Meta{Deterministic: true})
	if err != nil {
		t.Fatal(err)
	}
	data, err := Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if !utf8.Valid(data) {
		t.Error("invalid UTF-8 in the output")
	}
}
