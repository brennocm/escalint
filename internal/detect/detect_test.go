package detect

import (
	"strings"
	"testing"
)

func mustDefault(t *testing.T) *Catalog {
	t.Helper()
	c, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestForStepVisibility(t *testing.T) {
	c := mustDefault(t)
	tests := []struct {
		name    string
		kind    string
		actions []string
		want    Visibility
		event   string
	}{
		{"self escalation is visible", "modify_permissions", []string{"iam:PutRolePolicy"}, Visible, "iam.amazonaws.com/PutRolePolicy"},
		{"assume is partial (read-only event)", "assume", []string{"sts:AssumeRole"}, Partial, "sts.amazonaws.com/AssumeRole"},
		{"passrole + lambda is partial", "passrole_compute", []string{"iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"}, Partial, "lambda.amazonaws.com/CreateFunction20150331"},
		{"structural edges have no step", "admin", nil, Visible, ""},
	}
	for _, tc := range tests {
		s := c.ForStep(tc.kind, tc.actions)
		if s.Visibility != tc.want {
			t.Errorf("%s: visibility = %s, want %s (blind spots %v)", tc.name, s.Visibility, tc.want, s.BlindSpots)
		}
		if tc.event != "" && !hasEvent(s, tc.event) {
			t.Errorf("%s: missing event %s in %+v", tc.name, tc.event, s.Events)
		}
	}
	pass := c.ForStep("passrole_compute", []string{"iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"})
	if !pass.RequiresDataEvents || !anyContains(pass.BlindSpots, "not an API call") {
		t.Errorf("PassRole step must name the PassRole blind spot and need data events: %+v", pass)
	}
}

func TestForStepOnlyDataEventsIsBlind(t *testing.T) {
	c := mustDefault(t)
	if s := c.ForStep("update_code", []string{"lambda:InvokeFunction"}); s.Visibility != Blind {
		t.Errorf("invoke only = %s", s.Visibility)
	}
	if s := c.ForStep("passrole_compute", []string{"iam:PassRole"}); s.Visibility != Blind {
		t.Errorf("PassRole alone produces no event, got %s", s.Visibility)
	}
}

func TestForStepUnknownActionIsExplicit(t *testing.T) {
	s := mustDefault(t).ForStep("credential", []string{"iam:NoSuchAction"})
	if s.Status != Experimental || !anyContains(s.BlindSpots, "No detection data for iam:NoSuchAction") {
		t.Errorf("unknown action = %+v", s)
	}
}

func TestEveryActionHasEventsOrBlindSpots(t *testing.T) {
	c := mustDefault(t)
	for _, a := range c.actions {
		if len(a.Events) == 0 && len(a.BlindSpots) == 0 {
			t.Errorf("%s has neither events nor blind spots", a.Action)
		}
		seen := map[string]bool{}
		for _, e := range a.Events {
			if !strings.HasSuffix(e.Source, ".amazonaws.com") {
				t.Errorf("%s: eventSource %q", a.Action, e.Source)
			}
			if seen[e.Name] {
				t.Errorf("%s: duplicate event %s", a.Action, e.Name)
			}
			seen[e.Name] = true
		}
	}
	if _, ok := c.Action("IAM:PutRolePolicy"); !ok {
		t.Error("lookup must ignore case")
	}
	if _, ok := c.EdgeKind("assume"); !ok {
		t.Error("edge kind hints missing")
	}
}

func TestDecodeErrors(t *testing.T) {
	if _, err := Decode([]byte("{")); err == nil {
		t.Error("invalid JSON accepted")
	}
	if _, err := Decode([]byte(`{"actions":[{"action":"a:B"},{"action":"A:b"}]}`)); err == nil {
		t.Error("duplicate action accepted")
	}
}

func hasEvent(s Step, key string) bool {
	for _, e := range s.Events {
		if e.Source+"/"+e.Name == key {
			return true
		}
	}
	return false
}

func anyContains(list []string, sub string) bool {
	for _, s := range list {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
