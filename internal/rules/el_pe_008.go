package rules

import "github.com/brennocm/escalint/internal/graph"

// EL-PE-008: add itself to a more privileged group (pathfinding.cloud iam-013).
func elPE008() Rule {
	m := Metadata{
		ID: "EL-PE-008", Title: "Add itself to a more privileged group",
		Category: SelfEscalation, Severity: High, EdgeKind: graph.EdgeModifyPermissions,
		PathfindingIDs:  []string{"iam-013"},
		RequiredActions: []string{"iam:AddUserToGroup"},
		Prerequisites:   []string{"the actor is a user that is not yet a member"},
		Status:          Stable,
		Attack:          []string{"T1098.003"},
		Remediation:     "Scope iam:AddUserToGroup to specific groups and never allow it on groups with administrative policies.",
		References:      []string{"https://docs.aws.amazon.com/IAM/latest/APIReference/API_AddUserToGroup.html", "https://cwe.mitre.org/data/definitions/269.html"},
	}
	return pairRule{meta: m, targetKind: graph.NodeGroup, actorKinds: []graph.NodeKind{graph.NodeUser}, prereqs: notMember}
}
