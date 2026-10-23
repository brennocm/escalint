package rules

import "github.com/brennocm/escalint/internal/graph"

// EL-PE-020: modify a role's permissions and rewrite its trust (pathfinding.cloud iam-019, iam-020, iam-021).
func elPE020() Rule {
	m := Metadata{
		ID: "EL-PE-020", Title: "Modify a role's permissions and rewrite its trust",
		Category: PrincipalAccess, Severity: Critical, EdgeKind: graph.EdgeModifyPermissions,
		PathfindingIDs:  []string{"iam-019", "iam-020", "iam-021"},
		RequiredActions: []string{"iam:AttachRolePolicy", "iam:CreatePolicyVersion", "iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy"},
		Prerequisites:   []string{"one of the permission actions plus iam:UpdateAssumeRolePolicy on the role"},
		Status:          Stable,
		Attack:          []string{"T1098.003"},
		Remediation:     "Remove the permission-management action on other principals, or deny it in a permissions boundary; also review how the caller can act as the target.",
		References:      []string{"https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateAssumeRolePolicy.html", "https://cwe.mitre.org/data/definitions/269.html"},
	}
	return compositeRule{meta: m, modify: []string{"iam:AttachRolePolicy", "iam:CreatePolicyVersion", "iam:PutRolePolicy"}, targetKind: graph.NodeRole, actAs: []graph.EdgeKind{graph.EdgeModifyTrust}}
}
