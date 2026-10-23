package collect

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/brennocm/escalint/internal/engine"
	"github.com/brennocm/escalint/internal/snapshot"
)

func fixedNow() time.Time { return time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC) }

func clients() Clients {
	return Clients{
		STS: &fakeSTS{}, IAM: &fakeIAM{}, Organizations: &fakeOrg{rcpDisabled: true},
		Regions: []Regional{{Region: "us-east-1", Lambda: fakeLambda{}, EC2: fakeEC2{}, SSM: fakeSSM{}, CodeBuild: fakeCodeBuild{}}},
	}
}

func TestCollectRoundTrip(t *testing.T) {
	ctx := context.Background()
	c := clients()
	account, partition, err := Identity(ctx, c.STS)
	if err != nil || account != acct || partition != "aws" {
		t.Fatalf("identity = %s %s %v", account, partition, err)
	}
	var log bytes.Buffer
	opts := Options{Extras: true, Log: &log, Now: fixedNow, Version: "test"}
	a, err := ReadAccount(ctx, c, account, partition, opts)
	if err != nil {
		t.Fatal(err)
	}
	org, err := ReadOrganization(ctx, c.Organizations, opts)
	if err != nil {
		t.Fatal(err)
	}
	env := NewEnvelope(partition, []*Account{a}, org, opts)
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	snap, err := snapshot.Load(bytes.NewReader(data), snapshot.Options{})
	if err != nil {
		t.Fatalf("collected snapshot does not load: %v", err)
	}
	if snap.Format != snapshot.FormatEnvelope || len(snap.Accounts) != 1 || snap.Organization == nil || !snap.CollectedAt.Equal(fixedNow()) {
		t.Fatalf("snapshot = %+v", snap)
	}
	sa := snap.Accounts[0]
	if len(sa.Users) != 2 || len(sa.Roles) != 1 || len(sa.Groups) != 1 || sa.Extras == nil || sa.Extras.AccessKeys["arn:aws:iam::"+acct+":user/alice"] != 2 || !sa.Extras.LoginProfiles["arn:aws:iam::"+acct+":user/alice"] {
		t.Errorf("account = users %d roles %d groups %d extras %+v", len(sa.Users), len(sa.Roles), len(sa.Groups), sa.Extras)
	}
	if sa.Resources == nil || len(sa.Resources.Lambda) != 1 || len(sa.Resources.EC2) != 2 || len(sa.Resources.CodeBuild) != 1 || !sa.Resources.EC2[0].SSMManaged && !sa.Resources.EC2[1].SSMManaged {
		t.Errorf("resources = %+v", sa.Resources)
	}
	// Documents are decoded objects, except the invalid one, kept as a
	// string and reported by the loader.
	if !strings.Contains(string(data), `"Action": "iam:CreateAccessKey"`) || !strings.Contains(string(data), `"not%20json"`) {
		t.Errorf("documents not decoded:\n%s", data)
	}
	found := false
	for _, d := range snap.Diagnostics {
		if d.Code == snapshot.CodeParse && strings.Contains(d.Policy, "Boundary") {
			found = true
		}
	}
	if !found {
		t.Errorf("invalid document not diagnosed: %+v", snap.Diagnostics)
	}
	if !strings.Contains(string(data), `"Value": "a+b"`) {
		t.Error("tag values must keep '+'")
	}
	if len(org.Policies) != 1 || org.Policies[0].Targets[0] != "r-ab12" || len(org.Tree) != 4 {
		t.Errorf("org = %+v", org)
	}
	if !strings.Contains(log.String(), "RESOURCE_CONTROL_POLICY is not enabled") {
		t.Errorf("log = %s", log.String())
	}
	if _, err := engine.Run(snap, engine.Options{}); err != nil {
		t.Fatal(err)
	}
	// The envelope never carries access key IDs or credentials.
	if strings.Contains(string(data), "AKIA") || strings.Contains(string(data), "ASIA") {
		t.Error("credential material in the snapshot")
	}
}

func TestOrganizationWithRCPs(t *testing.T) {
	org, err := ReadOrganization(context.Background(), &fakeOrg{}, Options{})
	if err != nil || len(org.Policies) != 2 {
		t.Fatalf("org = %+v %v", org, err)
	}
}

func TestErrorsPropagate(t *testing.T) {
	c := clients()
	c.IAM = &fakeIAM{failExtras: true}
	if _, err := ReadAccount(context.Background(), c, acct, "aws", Options{Extras: true}); err == nil || !strings.Contains(err.Error(), "iam:ListAccessKeys") {
		t.Errorf("err = %v", err)
	}
}

func TestAssumeAndResources(t *testing.T) {
	s := &fakeSTS{}
	creds, err := Assume(context.Background(), s, "arn:aws:iam::222222222222:role/escalint-collector")
	if err != nil || creds == nil || s.assumed[0] != "arn:aws:iam::222222222222:role/escalint-collector" {
		t.Errorf("assume = %+v %v", creds, err)
	}
	got, err := ParseResources([]string{"lambda", " EC2 ", ""})
	if err != nil || !got["lambda"] || !got["ec2"] || got["codebuild"] {
		t.Errorf("resources = %v %v", got, err)
	}
	if _, err := ParseResources([]string{"s3"}); err == nil {
		t.Error("s3 accepted")
	}
	if d := decodeDocument(nil); string(d) != "null" {
		t.Errorf("nil document = %s", d)
	}
	if d := decodeDocument(stringPtr(`{"a":1}`)); string(d) != `{"a":1}` {
		t.Errorf("plain JSON document = %s", d)
	}
}

func stringPtr(s string) *string { return &s }
