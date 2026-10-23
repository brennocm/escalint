package snapshot

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const acct = "111111111111"

func load(t *testing.T, name string) *Snapshot {
	t.Helper()
	snap, err := LoadFile(filepath.Join("testdata", name), Options{})
	if err != nil {
		t.Fatalf("LoadFile(%s) error = %v", name, err)
	}
	return snap
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestLoadAuthorizationDetailsCLI(t *testing.T) {
	snap := load(t, "authz-cli.json")
	if snap.Format != FormatAuthorizationDetails || snap.Partition != "aws" || len(snap.Accounts) != 1 {
		t.Fatalf("snapshot = %+v", snap)
	}
	if len(snap.Diagnostics) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", snap.Diagnostics)
	}
	a := snap.Accounts[0]
	if a.ID != acct || len(a.Users) != 2 || len(a.Groups) != 1 || len(a.Roles) != 3 || len(a.Policies) != 3 {
		t.Fatalf("account counts: users=%d groups=%d roles=%d policies=%d", len(a.Users), len(a.Groups), len(a.Roles), len(a.Policies))
	}

	t.Run("users sorted and resolved", func(t *testing.T) {
		alice, ci := a.Users[0], a.Users[1]
		if alice.Name != "alice" || ci.Name != "ci-deployer" {
			t.Fatalf("user order = %s, %s", alice.Name, ci.Name)
		}
		if len(alice.Groups) != 1 || alice.Groups[0] != a.Group("developers") {
			t.Errorf("alice groups = %+v", alice.Groups)
		}
		if got := []Tag{{"env", "dev"}, {"team", "platform"}}; !reflect.DeepEqual(alice.Tags, got) {
			t.Errorf("tags not sorted: %+v", alice.Tags)
		}
		if len(alice.Inline) != 1 || alice.Inline[0].Document == nil {
			t.Errorf("alice inline = %+v", alice.Inline)
		}
		if ci.PermissionsBoundary != "arn:aws:iam::111111111111:policy/NoIAM" {
			t.Errorf("boundary = %q", ci.PermissionsBoundary)
		}
		if !reflect.DeepEqual(ci.Attached, []string{"arn:aws:iam::111111111111:policy/DevLambda"}) {
			t.Errorf("attached = %v", ci.Attached)
		}
	})

	t.Run("managed policy uses the default version", func(t *testing.T) {
		dev := a.Policy("arn:aws:iam::111111111111:policy/DevLambda")
		if dev == nil || dev.DefaultVersion != "v2" || dev.AWSManaged {
			t.Fatalf("DevLambda = %+v", dev)
		}
		if sid := dev.Document.Statements[0].Sid; sid != "AllowPassRole" {
			t.Errorf("default version not used: first Sid = %q", sid)
		}
		if admin := a.Policy("arn:aws:iam::aws:policy/AdministratorAccess"); admin == nil || !admin.AWSManaged {
			t.Errorf("AdministratorAccess = %+v", admin)
		}
		if a.Policy("arn:aws:iam::aws:policy/Nope") != nil {
			t.Error("unknown policy resolved")
		}
	})

	t.Run("roles", func(t *testing.T) {
		byName := map[string]*Role{}
		for _, r := range a.Roles {
			byName[r.Name] = r
		}
		lambda := byName["LambdaExecAdmin"]
		if lambda.Trust == nil || lambda.Trust.Statements[0].Principal.Service[0] != "lambda.amazonaws.com" {
			t.Errorf("trust = %+v", lambda.Trust)
		}
		want := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)
		if lambda.LastUsed == nil || !lambda.LastUsed.Equal(want) {
			t.Errorf("LastUsed = %v", lambda.LastUsed)
		}
		deploy := byName["AppDeployRole"]
		if deploy.LastUsed != nil {
			t.Errorf("empty RoleLastUsed must give nil, got %v", deploy.LastUsed)
		}
		if !reflect.DeepEqual(deploy.InstanceProfiles, []string{"arn:aws:iam::111111111111:instance-profile/AppDeploy"}) {
			t.Errorf("instance profiles = %v", deploy.InstanceProfiles)
		}
		if !byName["AWSServiceRoleForAutoScaling"].ServiceLinked || lambda.ServiceLinked {
			t.Error("ServiceLinked flag wrong")
		}
	})
}

// Edge case E34 (docs/research.md): URL-encoded documents (API/SDK) and JSON
// objects (CLI) must load to the same model.
func TestE34URLEncodedAndObjectDocumentsAreEquivalent(t *testing.T) {
	cli := load(t, "authz-cli.json")
	sdk := load(t, "authz-sdk.json")
	if !reflect.DeepEqual(cli, sdk) {
		t.Fatal("CLI and SDK snapshots load to different models")
	}
	res := sdk.Accounts[0].Policy("arn:aws:iam::111111111111:policy/DevLambda").Document.Statements[1].Resource[0]
	if res != "arn:aws:s3:::example-bucket/a+b/*" {
		t.Errorf("'+' not preserved through URL decoding: %q", res)
	}
}

func TestLoadEnvelope(t *testing.T) {
	snap := load(t, "envelope.json")
	if snap.Format != FormatEnvelope || !snap.CollectedAt.Equal(time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("snapshot header = %+v", snap)
	}
	a := snap.Accounts[0]
	if a.Extras == nil || a.Extras.AccessKeys["arn:aws:iam::111111111111:user/ci/ci-deployer"] != 2 || !a.Extras.LoginProfiles["arn:aws:iam::111111111111:user/alice"] {
		t.Errorf("extras = %+v", a.Extras)
	}
	if a.Resources == nil || len(a.Resources.Lambda) != 1 || a.Resources.Lambda[0].Role != "arn:aws:iam::111111111111:role/LambdaExecAdmin" {
		t.Errorf("resources = %+v", a.Resources)
	}
	if len(a.IdentityProviders.OIDC) != 1 || a.IdentityProviders.OIDC[0].URL != "https://token.actions.githubusercontent.com" {
		t.Errorf("identity providers = %+v", a.IdentityProviders)
	}

	org := snap.Organization
	if org == nil || org.ManagementAccountID != "222222222222" || len(org.Nodes) != 4 || len(org.Policies) != 3 {
		t.Fatalf("organization = %+v", org)
	}
	path, err := org.PathTo(acct)
	if err != nil || !reflect.DeepEqual(path, []string{"r-ab12", "ou-ab12-workloads", acct}) {
		t.Errorf("PathTo = %v, %v", path, err)
	}
	if _, err := org.PathTo("ou-ab12-workloads"); err == nil {
		t.Error("PathTo(OU) must fail: only accounts have paths")
	}
	scps := org.PoliciesAttachedTo("ou-ab12-workloads", PolicySCP)
	if len(scps) != 2 || scps[0].ID != "p-FullAWSAccess" || scps[1].ID != "p-denyleave" {
		t.Errorf("SCPs on OU = %+v", scps)
	}
	if scps[1].Document == nil || scps[1].Document.Statements[0].Effect != "Deny" {
		t.Error("SCP given as a JSON string was not parsed")
	}
	if rcps := org.PoliciesAttachedTo("r-ab12", PolicyRCP); len(rcps) != 1 || rcps[0].Document == nil {
		t.Errorf("RCPs on root = %+v", rcps)
	}
}

func TestLoadKeepsGoingWithDiagnostics(t *testing.T) {
	snap := load(t, "authz-diagnostics.json")
	type key struct{ code, policy, path string }
	got := map[key]bool{}
	for _, d := range snap.Diagnostics {
		got[key{d.Code, d.Policy, d.Path}] = true
		if d.Account != acct || d.Entity != "arn:aws:iam::111111111111:user/alice" || d.Message == "" {
			t.Errorf("diagnostic without context: %+v", d)
		}
	}
	for _, want := range []key{
		{CodeParse, "broken", "Statement.Effect"},
		{CodeUnresolved, "arn:aws:iam::aws:policy/ReadOnlyAccess", ""},
		{CodeUnresolved, "", ""},
	} {
		if !got[want] {
			t.Errorf("missing diagnostic %+v in %+v", want, snap.Diagnostics)
		}
	}
	alice := snap.Accounts[0].Users[0]
	if len(alice.Inline) != 2 || alice.Inline[0].Name != "broken" || alice.Inline[0].Document != nil || alice.Inline[1].Document == nil {
		t.Errorf("broken policy must be kept with a nil document and the rest parsed: %+v", alice.Inline)
	}
}

func TestLoadAcceptsUTF8BOM(t *testing.T) {
	data := append([]byte("\xef\xbb\xbf"), readFixture(t, "authz-cli.json")...)
	if _, err := Load(bytes.NewReader(data), Options{}); err != nil {
		t.Fatalf("Load() with BOM error = %v", err)
	}
}

func TestLoadErrors(t *testing.T) {
	envelope := func(mutate func(map[string]any)) string {
		var m map[string]any
		if err := json.Unmarshal(readFixture(t, "envelope.json"), &m); err != nil {
			t.Fatal(err)
		}
		mutate(m)
		out, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	org := func(m map[string]any) map[string]any { return m["organization"].(map[string]any) }
	firstAccount := func(m map[string]any) map[string]any {
		return m["accounts"].([]any)[0].(map[string]any)
	}
	tree := func(m map[string]any) []any { return org(m)["tree"].([]any) }

	tests := []struct {
		name    string
		input   string
		opts    Options
		wantErr string
		limit   bool
	}{
		{"invalid json", `{"UserDetailList":`, Options{}, "invalid JSON", false},
		{"not an object", `[]`, Options{}, "must be a JSON object", false},
		{"unknown format", `{"Foo":1}`, Options{}, "unknown format", false},
		{"duplicate key in snapshot", `{"UserDetailList":[],"UserDetailList":[]}`, Options{}, "duplicate key", false},
		{"too big", `{"UserDetailList":[]}`, Options{MaxBytes: 5}, "larger than", true},
		{"too deep", strings.Repeat("[", 70) + strings.Repeat("]", 70), Options{}, "nesting", true},
		{"no customer arn", `{"Policies":[]}`, Options{}, "cannot infer the account", false},
		{"bad arn", `{"UserDetailList":[{"Arn":"nope"}]}`, Options{}, "does not have the form", false},
		{"mixed accounts", `{"UserDetailList":[{"Arn":"arn:aws:iam::111111111111:user/a"},{"Arn":"arn:aws:iam::222222222222:user/b"}]}`, Options{}, "does not belong to account", false},
		{"non iam entity", `{"RoleDetailList":[{"Arn":"arn:aws:s3:::111111111111"}]}`, Options{}, "cannot infer", false},
		{"duplicate user", `{"UserDetailList":[{"Arn":"arn:aws:iam::111111111111:user/a"},{"Arn":"arn:aws:iam::111111111111:user/a"}]}`, Options{}, "appears twice", false},
		{"duplicate group", `{"GroupDetailList":[{"GroupName":"g","Arn":"arn:aws:iam::111111111111:group/g"},{"GroupName":"g","Arn":"arn:aws:iam::111111111111:group/g"}]}`, Options{}, "appears twice", false},
		{"mixed partitions", `{"UserDetailList":[{"Arn":"arn:aws:iam::111111111111:user/a"},{"Arn":"arn:aws-cn:iam::111111111111:user/b"}]}`, Options{}, "mixes partitions", false},
		{"bad last used", `{"RoleDetailList":[{"Arn":"arn:aws:iam::111111111111:role/r","RoleLastUsed":{"LastUsedDate":"yesterday"}}]}`, Options{}, "LastUsedDate", false},
		{"too many principals", `{"UserDetailList":[{"Arn":"arn:aws:iam::111111111111:user/a"},{"Arn":"arn:aws:iam::111111111111:user/b"}]}`, Options{MaxPrincipals: 1}, "more than 1 principals", true},
		{"envelope version", envelope(func(m map[string]any) { m["escalint_snapshot"] = "2" }), Options{}, `version "2"`, false},
		{"envelope no accounts", envelope(func(m map[string]any) { m["accounts"] = []any{} }), Options{}, "no accounts", false},
		{"envelope bad account id", envelope(func(m map[string]any) { firstAccount(m)["account_id"] = "123" }), Options{}, "12-digit", false},
		{"envelope duplicate account", envelope(func(m map[string]any) { m["accounts"] = append(m["accounts"].([]any), firstAccount(m)) }), Options{}, "appears twice", false},
		{"envelope bad time", envelope(func(m map[string]any) { m["collected_at"] = "today" }), Options{}, "collected_at", false},
		{"org two roots", envelope(func(m map[string]any) {
			org(m)["tree"] = append(tree(m), map[string]any{"id": "r-other", "type": "ROOT"})
		}), Options{}, "exactly one root", false},
		{"org unknown parent", envelope(func(m map[string]any) {
			tree(m)[1].(map[string]any)["parent"] = "ou-missing"
		}), Options{}, "unknown parent", false},
		{"org cycle", envelope(func(m map[string]any) {
			org(m)["tree"] = append(tree(m),
				map[string]any{"id": "ou-a", "type": "ORGANIZATIONAL_UNIT", "parent": "ou-b"},
				map[string]any{"id": "ou-b", "type": "ORGANIZATIONAL_UNIT", "parent": "ou-a"},
				map[string]any{"id": "333333333333", "type": "ACCOUNT", "parent": "ou-a"})
		}), Options{}, "cycle", false},
		{"org bad node type", envelope(func(m map[string]any) { tree(m)[1].(map[string]any)["type"] = "FOLDER" }), Options{}, "unknown type", false},
		{"org root with parent", envelope(func(m map[string]any) { tree(m)[0].(map[string]any)["parent"] = "x" }), Options{}, "cannot have a parent", false},
		{"org orphan ou", envelope(func(m map[string]any) { tree(m)[1].(map[string]any)["parent"] = nil }), Options{}, "has no parent", false},
		{"org bad policy type", envelope(func(m map[string]any) {
			org(m)["policies"].([]any)[0].(map[string]any)["type"] = "TAG_POLICY"
		}), Options{}, "unknown type", false},
		{"org unknown target", envelope(func(m map[string]any) {
			org(m)["policies"].([]any)[0].(map[string]any)["targets"] = []any{"ou-missing"}
		}), Options{}, "unknown node", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(strings.NewReader(tc.input), tc.opts)
			if err == nil {
				t.Fatal("Load() error = nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
			}
			if tc.limit != errors.Is(err, ErrLimitExceeded) {
				t.Errorf("errors.Is(err, ErrLimitExceeded) = %v, want %v", !tc.limit, tc.limit)
			}
		})
	}
}

func TestDecodeDocument(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr string
	}{
		{"object", `{"Version":"2012-10-17"}`, `{"Version":"2012-10-17"}`, ""},
		{"json string", `"{\"Statement\":[]}"`, `{"Statement":[]}`, ""},
		{"json string with spaces", `"  {\"a\":1}"`, `  {"a":1}`, ""},
		{"url encoded", `"%7B%22Statement%22%3A%5B%5D%7D"`, `{"Statement":[]}`, ""},
		{"plus is not a space", `"%7B%22a%22%3A%22x+y%22%7D"`, `{"a":"x+y"}`, ""},
		{"percent inside plain json", `"{\"a\":\"50%\"}"`, `{"a":"50%"}`, ""},
		{"bad escape", `"%7B%zz"`, "", "URL encoding"},
		{"null", `null`, "", "missing"},
		{"empty", ``, "", "missing"},
		{"number", `5`, "", "object or a string"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeDocument(json.RawMessage(tc.raw))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("DecodeDocument() error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || string(got) != tc.want {
				t.Errorf("DecodeDocument() = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestLoadIsDeterministic(t *testing.T) {
	data := readFixture(t, "envelope.json")
	first, err := Load(bytes.NewReader(data), Options{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := Load(bytes.NewReader(data), Options{})
		if err != nil || !reflect.DeepEqual(first, again) {
			t.Fatalf("run %d differs", i)
		}
	}
}

func TestLoadFileMissing(t *testing.T) {
	if _, err := LoadFile(filepath.Join("testdata", "missing.json"), Options{}); err == nil || !strings.Contains(err.Error(), "open snapshot") {
		t.Fatalf("LoadFile() error = %v", err)
	}
}

func FuzzLoadSnapshot(f *testing.F) {
	for _, name := range []string{"authz-cli.json", "authz-sdk.json", "envelope.json", "authz-diagnostics.json"} {
		data, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		snap, err := Load(bytes.NewReader(data), Options{MaxBytes: 1 << 20})
		if err != nil {
			return
		}
		for _, a := range snap.Accounts {
			for i := 1; i < len(a.Users); i++ {
				if a.Users[i-1].ARN >= a.Users[i].ARN {
					t.Fatalf("users not sorted or duplicated")
				}
			}
		}
	})
}
