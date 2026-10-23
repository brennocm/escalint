package rules

import "github.com/brennocm/escalint/internal/graph"

// EL-PE-007: put an inline policy on its own group (pathfinding.cloud iam-011).
func elPE007() Rule {
	m := Metadata{
		ID: "EL-PE-007", Title: "Put an inline policy on its own group",
		Category: SelfEscalation, Severity: Critical, EdgeKind: graph.EdgeModifyPermissions,
		PathfindingIDs:  []string{"iam-011"},
		RequiredActions: []string{"iam:PutGroupPolicy"},
		Prerequisites:   []string{"the actor is a member of the group"},
		Status:          Stable,
		Attack:          []string{"T1098.003"},
		Remediation:     "Remove the action from the principal's policies, scope its Resource to other entities, or add a permissions boundary that denies it.",
		References:      []string{"https://docs.aws.amazon.com/IAM/latest/APIReference/API_PutGroupPolicy.html", "https://cwe.mitre.org/data/definitions/269.html"},
	}
	return selfRule{meta: m, kinds: []graph.NodeKind{graph.NodeUser}, targets: groupsOf}
}
