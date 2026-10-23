package rules

import "github.com/brennocm/escalint/internal/graph"

// assumeRule documents EL-PE-014. The graph builder adds assume edges
// itself (they are needed before any rule runs), so Apply does nothing.
type assumeRule struct{ meta Metadata }

func (r assumeRule) Meta() Metadata           { return r.meta }
func (r assumeRule) Pass() Pass               { return PassPrimitive }
func (r assumeRule) Apply(*Context) []Finding { return nil }

// EL-PE-014: assume a more privileged role (pathfinding.cloud sts-001).
func elPE014() Rule {
	return assumeRule{meta: Metadata{
		ID: graph.RuleAssume, Title: "Assume a more privileged role",
		Category: PrincipalAccess, Severity: Medium, EdgeKind: graph.EdgeAssume,
		PathfindingIDs:  []string{graph.PathfindingSTS1},
		RequiredActions: []string{"sts:AssumeRole"},
		Prerequisites:   []string{"the role's trust policy accepts the actor (docs/research.md §2.4)"},
		Status:          Stable,
		Attack:          []string{"T1548.005", "T1078.004"},
		Remediation:     "Name only the principals that need the role in its trust policy, add conditions (sts:ExternalId, aws:PrincipalOrgID, MFA) and scope sts:AssumeRole in identity policies to specific role ARNs.",
		References: []string{
			"https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html",
			"https://cwe.mitre.org/data/definitions/269.html",
		},
	}}
}
