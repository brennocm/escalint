package rules

import "github.com/brennocm/escalint/internal/graph"

// EL-PE-019: put an inline policy on a user and create its access key (pathfinding.cloud iam-018).
func elPE019() Rule {
	m := Metadata{
		ID: "EL-PE-019", Title: "Put an inline policy on a user and create its access key",
		Category: PrincipalAccess, Severity: Critical, EdgeKind: graph.EdgeModifyPermissions,
		PathfindingIDs:  []string{"iam-018"},
		RequiredActions: []string{"iam:PutUserPolicy", "iam:CreateAccessKey"},
		Prerequisites:   []string{"the actor can create credentials for the user"},
		Status:          Stable,
		Attack:          []string{"T1098.003", "T1098.001"},
		Remediation:     "Remove the permission-management action on other principals, or deny it in a permissions boundary; also review how the caller can act as the target.",
		References:      []string{"https://docs.aws.amazon.com/IAM/latest/APIReference/API_PutUserPolicy.html", "https://cwe.mitre.org/data/definitions/269.html"},
	}
	return compositeRule{meta: m, modify: []string{"iam:PutUserPolicy"}, targetKind: graph.NodeUser, actAs: []graph.EdgeKind{graph.EdgeCredential}}
}
