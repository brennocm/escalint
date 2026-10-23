package suppress

import (
	"testing"
	"time"

	"github.com/brennocm/escalint/internal/config"
	"github.com/brennocm/escalint/internal/contract"
)

func ptr(s string) *string { return &s }

func analysis() *contract.Analysis {
	return &contract.Analysis{
		Nodes: []contract.Node{
			{ID: "n_1", ARN: ptr("arn:aws:iam::111111111111:role/legacy-partner")},
			{ID: "n_2", ARN: ptr("arn:aws:iam::111111111111:user/alice")},
			{ID: "n_3", Kind: "service", Name: "lambda.amazonaws.com"},
		},
		Findings: []contract.Finding{
			{ID: "f_1", RuleID: "EL-TR-004", Severity: "medium", NodeID: ptr("n_1")},
			{ID: "f_2", RuleID: "EL-PE-022", Severity: "critical", NodeID: ptr("n_2")},
			{ID: "f_3", RuleID: "EL-PARSE-002", Severity: "info", Location: contract.Location{Entity: "arn:aws:iam::111111111111:user/alice"}},
		},
	}
}

var now = time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)

func TestApply(t *testing.T) {
	a := analysis()
	f := &config.File{Source: "cfg.yaml", Suppressions: []config.Suppression{
		{Rule: "EL-TR-*", ARN: "arn:aws:iam::111111111111:role/legacy-*", Reason: "approved (SEC-1)", Expires: "2027-01-31"},
		{Rule: "EL-PE-022", ARN: "*", Reason: "old", Expires: "2026-01-01"},
		{Rule: "EL-PARSE-*", ARN: "arn:aws:iam::111111111111:user/*", Reason: "  "},
	}}
	Apply(a, f, now)
	byID := map[string]contract.Finding{}
	for _, fd := range a.Findings {
		byID[fd.ID] = fd
	}
	if s := byID["f_1"].Suppressed; s == nil || s.Reason != "approved (SEC-1)" || *s.Expires != "2027-01-31" || s.Source != "cfg.yaml#suppressions[0]" {
		t.Errorf("f_1 suppressed = %+v", s)
	}
	if byID["f_2"].Suppressed != nil {
		t.Error("expired suppression still suppresses")
	}
	if byID["f_3"].Suppressed != nil {
		t.Error("unjustified suppression suppresses")
	}
	statuses := []string{a.Suppressions[0].Status, a.Suppressions[1].Status, a.Suppressions[2].Status}
	if statuses[0] != Active || statuses[1] != Expired || statuses[2] != Unjustified {
		t.Errorf("statuses = %v", statuses)
	}
	if len(a.Suppressions[1].Findings) != 1 || a.Suppressions[1].Findings[0] != "f_2" {
		t.Errorf("expired entry findings = %v", a.Suppressions[1].Findings)
	}
	var unjustified []contract.Finding
	for _, fd := range a.Findings {
		if fd.RuleID == RuleUnjustified {
			unjustified = append(unjustified, fd)
		}
	}
	if len(unjustified) != 1 || unjustified[0].Location.Path != "suppressions[2]" || unjustified[0].Severity != "info" {
		t.Errorf("unjustified findings = %+v", unjustified)
	}
	if a.Findings[0].Severity != "critical" || a.Stats.Findings != 4 {
		t.Errorf("findings not re-sorted or counted: %+v", a.Findings)
	}
	Apply(a, nil, now) // no config: no change
}

func TestGroup(t *testing.T) {
	a := analysis()
	Group(a, &config.File{Groupings: []config.Grouping{
		{Name: "partners", ARNs: []string{"arn:aws:iam::*:role/legacy-*"}},
		{Name: "people", ARNs: []string{"arn:aws:iam::*:user/*", "arn:aws:iam::*:role/*"}},
		{Name: "empty", ARNs: []string{"arn:aws:iam::*:group/*"}},
	}})
	if *a.Nodes[0].Group != "partners" || *a.Nodes[1].Group != "people" || a.Nodes[2].Group != nil {
		t.Errorf("groups = %v %v %v", a.Nodes[0].Group, a.Nodes[1].Group, a.Nodes[2].Group)
	}
	if len(a.Groupings) != 3 || len(a.Groupings[2].Nodes) != 0 || a.Groupings[2].Nodes == nil {
		t.Errorf("groupings = %+v", a.Groupings)
	}
	Group(a, nil)
}
