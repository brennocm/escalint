package rules

import (
	"regexp"
	"strings"
	"testing"

	"github.com/brennocm/escalint/docs"
	"github.com/brennocm/escalint/internal/attack"
	"github.com/brennocm/escalint/internal/catalog"
	"github.com/brennocm/escalint/internal/detect"
)

var idPattern = regexp.MustCompile(`^EL-(PE|TR|PARSE)-\d{3}$`)

func TestRegistry(t *testing.T) {
	cat, err := catalog.Default()
	if err != nil {
		t.Fatal(err)
	}
	att, err := attack.Default()
	if err != nil {
		t.Fatal(err)
	}
	det, err := detect.Default()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	all := All()
	if len(all) == 0 {
		t.Fatal("empty registry")
	}
	for i, r := range all {
		m := r.Meta()
		t.Run(m.ID, func(t *testing.T) {
			if !idPattern.MatchString(m.ID) {
				t.Errorf("ID %q does not match %s", m.ID, idPattern)
			}
			if seen[m.ID] {
				t.Errorf("duplicate ID")
			}
			seen[m.ID] = true
			if i > 0 && all[i-1].Meta().ID >= m.ID {
				t.Errorf("registry not sorted")
			}
			if m.Title == "" || m.Remediation == "" || len(m.References) == 0 {
				t.Error("title, remediation and references are required")
			}
			if _, ok := ParseSeverity(string(m.Severity)); !ok {
				t.Errorf("severity %q", m.Severity)
			}
			if m.Status != Stable && m.Status != Experimental {
				t.Errorf("status %q", m.Status)
			}
			doc, ok := docs.Rule(m.ID)
			if !ok {
				t.Fatalf("docs/rules/%s.md is missing", m.ID)
			}
			for _, section := range []string{"## Description", "## Why it matters", "## Attack chain", "## Vulnerable example", "## Fixed example", "## References"} {
				if !strings.Contains(doc, section) {
					t.Errorf("doc misses %q", section)
				}
			}
			for _, a := range m.RequiredActions {
				if _, ok := cat.Lookup(a); !ok {
					t.Errorf("action %s is not in the AWS catalog", a)
				}
				if !strings.Contains(doc, a) {
					t.Errorf("doc does not mention %s", a)
				}
			}
			for _, p := range m.PathfindingIDs {
				if _, ok := Pathfinding()[p]; !ok {
					t.Errorf("pathfinding.cloud ID %s is not in the verified list", p)
				}
			}
			if len(m.Attack) == 0 && m.AttackUnmappedReason == "" {
				t.Error("needs ATT&CK techniques or AttackUnmappedReason")
			}
			for _, id := range m.Attack {
				if _, ok := att.Lookup(id); !ok {
					t.Errorf("ATT&CK %s is not an active IaaS technique in v%s", id, att.Version)
				}
			}
			if len(m.AttackRefs(att)) != len(m.Attack) {
				t.Error("every technique must resolve with a name from the bundle")
			}
			// Consistency (addendum §5): every required action has an event or
			// a blind spot that names it.
			for _, a := range m.RequiredActions {
				ad, ok := det.Action(a)
				if !ok {
					t.Errorf("no CloudTrail detection data for %s", a)
					continue
				}
				if len(ad.Events) == 0 {
					named := false
					for _, b := range ad.BlindSpots {
						named = named || strings.Contains(b, strings.SplitN(a, ":", 2)[1]) || strings.Contains(b, a)
					}
					if !named {
						t.Errorf("%s has no event and no blind spot that names it", a)
					}
				}
			}
		})
	}
	if _, ok := ByID("EL-PE-022"); !ok {
		t.Error("ByID")
	}
	if _, ok := ByID("EL-PE-999"); ok {
		t.Error("ByID found a missing rule")
	}
}

func TestPathfindingData(t *testing.T) {
	p := Pathfinding()
	if len(p) < 90 {
		t.Fatalf("pathfinding list has %d paths", len(p))
	}
	if iam := p["iam-001"]; iam.Category != "self-escalation" || !strings.HasPrefix(iam.Source, "https://github.com/DataDog/pathfinding.cloud/blob/") {
		t.Errorf("iam-001 = %+v", iam)
	}
}

func TestSeverity(t *testing.T) {
	if Critical.Rank() >= High.Rank() || Severity("x").Rank() != 5 {
		t.Error("Rank")
	}
	if _, ok := ParseSeverity("bogus"); ok {
		t.Error("ParseSeverity accepted bogus")
	}
}
