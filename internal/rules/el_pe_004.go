package rules

import "github.com/brennocm/escalint/internal/graph"

// EL-PE-004: attach a managed policy to its own user (pathfinding.cloud iam-008).
func elPE004() Rule {
	m := Metadata{
		ID: "EL-PE-004", Title: "Attach a managed policy to its own user",
		Category: SelfEscalation, Severity: Critical, EdgeKind: graph.EdgeModifyPermissions,
		PathfindingIDs:  []string{"iam-008"},
		RequiredActions: []string{"iam:AttachUserPolicy"},
		Prerequisites:   []string{"the actor is a user"},
		Status:          Stable,
		Attack:          []string{"T1098.003"},
		Remediation:     "Remove the action from the principal's policies, scope its Resource to other entities, or add a permissions boundary that denies it. A condition on iam:PolicyARN can limit which policies may be attached.",
		References:      []string{"https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachUserPolicy.html", "https://cwe.mitre.org/data/definitions/269.html"},
	}
	return selfRule{meta: m, kinds: []graph.NodeKind{graph.NodeUser}, targets: ownARN}
}
