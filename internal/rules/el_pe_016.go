package rules

import "github.com/brennocm/escalint/internal/graph"

// EL-PE-016: create a new policy version for a role it can assume (pathfinding.cloud iam-016).
func elPE016() Rule {
	m := Metadata{
		ID: "EL-PE-016", Title: "Create a new policy version for a role it can assume",
		Category: PrincipalAccess, Severity: Critical, EdgeKind: graph.EdgeModifyPermissions,
		PathfindingIDs:  []string{"iam-016"},
		RequiredActions: []string{"iam:CreatePolicyVersion", "sts:AssumeRole"},
		Prerequisites:   []string{"a customer managed policy is attached to the role", "the actor can already assume the role"},
		Status:          Stable,
		Attack:          []string{"T1098.003", "T1548.005"},
		Remediation:     "Remove the permission-management action on other principals, or deny it in a permissions boundary; also review how the caller can act as the target.",
		References:      []string{"https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreatePolicyVersion.html", "https://cwe.mitre.org/data/definitions/269.html"},
	}
	return compositeRule{meta: m, modify: []string{"iam:CreatePolicyVersion"}, targetKind: graph.NodeRole, actAs: []graph.EdgeKind{graph.EdgeAssume}}
}
