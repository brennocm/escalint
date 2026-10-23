package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brennocm/escalint/internal/detect"
)

func fakeOps(service string) (map[string][]string, error) {
	switch service {
	case "iam":
		return map[string][]string{"putrolepolicy": {"PutRolePolicy"}}, nil
	case "lambda":
		return map[string][]string{"createfunction": {"CreateFunction"}}, nil
	default:
		return nil, errors.New("unknown service")
	}
}

func TestEnrichAcceptsValidOverrides(t *testing.T) {
	f := &detect.File{Actions: []detect.ActionDetection{
		{
			Action: "lambda:CreateFunction", Operation: "CreateFunction", Status: detect.Verified,
			Events: []detect.Event{{Source: "lambda.amazonaws.com", Name: "CreateFunction20150331", Kind: detect.Management}},
		},
		{
			Action: "iam:PutRolePolicy", Operation: "PutRolePolicy", Status: detect.Verified,
			Events: []detect.Event{{Source: "iam.amazonaws.com", Name: "PutRolePolicy", Kind: detect.Management}},
		},
	}}
	if err := enrich(f, fakeOps); err != nil {
		t.Fatalf("enrich() error = %v", err)
	}
	if f.Actions[0].Action != "iam:PutRolePolicy" || len(f.Actions[0].Operations) != 1 {
		t.Errorf("actions not sorted or not enriched: %+v", f.Actions)
	}
}

func TestEnrichRejects(t *testing.T) {
	ev := func(src, name string, kind detect.EventKind) []detect.Event {
		return []detect.Event{{Source: src, Name: name, Kind: kind}}
	}
	tests := []struct {
		name string
		a    detect.ActionDetection
		want string
	}{
		{"wrong operation", detect.ActionDetection{Action: "iam:PutRolePolicy", Operation: "PutUserPolicy", Status: detect.Verified, Events: ev("iam.amazonaws.com", "PutUserPolicy", detect.Management)}, "does not authorize"},
		{"bad source", detect.ActionDetection{Action: "iam:PutRolePolicy", Operation: "PutRolePolicy", Status: detect.Verified, Events: ev("iam", "PutRolePolicy", detect.Management)}, "eventSource"},
		{"bad kind", detect.ActionDetection{Action: "iam:PutRolePolicy", Operation: "PutRolePolicy", Status: detect.Verified, Events: ev("iam.amazonaws.com", "PutRolePolicy", "insight")}, "event kind"},
		{"event name drift", detect.ActionDetection{Action: "iam:PutRolePolicy", Operation: "PutRolePolicy", Status: detect.Verified, Events: ev("iam.amazonaws.com", "AttachRolePolicy", detect.Management)}, "does not start with"},
		{"nothing at all", detect.ActionDetection{Action: "iam:PutRolePolicy", Operation: "PutRolePolicy", Status: detect.Verified}, "explicit blind spot"},
		{"bad status", detect.ActionDetection{Action: "iam:PutRolePolicy", Operation: "PutRolePolicy", Status: "maybe", BlindSpots: []string{"x"}}, "invalid status"},
		{"no prefix", detect.ActionDetection{Action: "PutRolePolicy", Status: detect.Verified}, "no service prefix"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := enrich(&detect.File{Actions: []detect.ActionDetection{tc.a}}, fakeOps)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("enrich() error = %v, want %q", err, tc.want)
			}
		})
	}
	if err := enrich(&detect.File{Actions: []detect.ActionDetection{{Action: "nope:X", Status: detect.Verified, BlindSpots: []string{"x"}}}}, fakeOps); err == nil {
		t.Error("fetch failure must stop generation")
	}
}

func TestReferenceGapSkipsOperationCheck(t *testing.T) {
	a := detect.ActionDetection{
		Action: "iam:Unmapped", Operation: "Unmapped", Status: detect.Verified, ReferenceGap: "documented elsewhere",
		Events: []detect.Event{{Source: "iam.amazonaws.com", Name: "Unmapped", Kind: detect.Management}},
	}
	if err := enrich(&detect.File{Actions: []detect.ActionDetection{a}}, fakeOps); err != nil {
		t.Errorf("enrich() error = %v", err)
	}
}

func TestParseOperations(t *testing.T) {
	ops, err := parseOperations([]byte(`{"Operations":[
		{"Name":"Invoke","AuthorizedActions":[{"Name":"InvokeFunction","Service":"lambda"}]},
		{"Name":"InvokeWithResponseStream","AuthorizedActions":[{"Name":"InvokeFunction","Service":"lambda"},{"Name":"PassRole","Service":"iam"}]}]}`), "lambda")
	if err != nil || strings.Join(ops["invokefunction"], ",") != "Invoke,InvokeWithResponseStream" || ops["passrole"] != nil {
		t.Errorf("parseOperations = %v, %v", ops, err)
	}
	if _, err := parseOperations([]byte("{"), "x"); err == nil {
		t.Error("invalid JSON accepted")
	}
}

func TestRun(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "overrides.json")
	if err := os.WriteFile(in, []byte(`{"format_version":1,"actions":[{"action":"iam:PutRolePolicy","operation":"PutRolePolicy","status":"verified",
		"events":[{"source":"iam.amazonaws.com","name":"PutRolePolicy","kind":"management"}]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(in, filepath.Join(dir, "detect.json"), fakeOps); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if err := run(filepath.Join(dir, "missing.json"), filepath.Join(dir, "x.json"), fakeOps); err == nil {
		t.Error("missing overrides accepted")
	}
}
