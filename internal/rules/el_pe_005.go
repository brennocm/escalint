package rules

import "github.com/brennocm/escalint/internal/graph"

// EL-PE-005: attach a managed policy to its own role (pathfinding.cloud iam-009).
func elPE005() Rule {
	m := Metadata{
		ID: "EL-PE-005", Title: "Attach a managed policy to its own role",
		Category: SelfEscalation, Severity: Critical, EdgeKind: graph.EdgeModifyPermissions,
		PathfindingIDs:  []string{"iam-009"},
		RequiredActions: []string{"iam:AttachRolePolicy"},
		Prerequisites:   []string{"the actor is a role"},
		Status:          Stable,
		Attack:          []string{"T1098.003"},
		Remediation:     "Remove the action from the principal's policies, scope its Resource to other entities, or add a permissions boundary that denies it. A condition on iam:PolicyARN can limit which policies may be attached.",
		References:      []string{"https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachRolePolicy.html", "https://cwe.mitre.org/data/definitions/269.html"},
	}
	return selfRule{meta: m, kinds: []graph.NodeKind{graph.NodeRole}, targets: ownARN}
}
