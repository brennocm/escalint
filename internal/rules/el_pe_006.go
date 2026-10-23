package rules

import "github.com/brennocm/escalint/internal/graph"

// EL-PE-006: attach a managed policy to its own group (pathfinding.cloud iam-010).
func elPE006() Rule {
	m := Metadata{
		ID: "EL-PE-006", Title: "Attach a managed policy to its own group",
		Category: SelfEscalation, Severity: Critical, EdgeKind: graph.EdgeModifyPermissions,
		PathfindingIDs:  []string{"iam-010"},
		RequiredActions: []string{"iam:AttachGroupPolicy"},
		Prerequisites:   []string{"the actor is a member of the group"},
		Status:          Stable,
		Attack:          []string{"T1098.003"},
		Remediation:     "Remove the action from the principal's policies, scope its Resource to other entities, or add a permissions boundary that denies it.",
		References:      []string{"https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachGroupPolicy.html", "https://cwe.mitre.org/data/definitions/269.html"},
	}
	return selfRule{meta: m, kinds: []graph.NodeKind{graph.NodeUser}, targets: groupsOf}
}
