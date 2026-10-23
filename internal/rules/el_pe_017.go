package rules

import "github.com/brennocm/escalint/internal/graph"

// EL-PE-017: put an inline policy on a role it can assume (pathfinding.cloud iam-017).
func elPE017() Rule {
	m := Metadata{
		ID: "EL-PE-017", Title: "Put an inline policy on a role it can assume",
		Category: PrincipalAccess, Severity: Critical, EdgeKind: graph.EdgeModifyPermissions,
		PathfindingIDs:  []string{"iam-017"},
		RequiredActions: []string{"iam:PutRolePolicy", "sts:AssumeRole"},
		Prerequisites:   []string{"the actor can already assume the role"},
		Status:          Stable,
		Attack:          []string{"T1098.003", "T1548.005"},
		Remediation:     "Remove the permission-management action on other principals, or deny it in a permissions boundary; also review how the caller can act as the target.",
		References:      []string{"https://docs.aws.amazon.com/IAM/latest/APIReference/API_PutRolePolicy.html", "https://cwe.mitre.org/data/definitions/269.html"},
	}
	return compositeRule{meta: m, modify: []string{"iam:PutRolePolicy"}, targetKind: graph.NodeRole, actAs: []graph.EdgeKind{graph.EdgeAssume}}
}
