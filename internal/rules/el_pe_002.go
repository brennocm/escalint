package rules

import "github.com/brennocm/escalint/internal/graph"

// EL-PE-002: a role adds an inline policy to itself (pathfinding.cloud iam-005).
func elPE002() Rule {
	return selfRule{
		meta: Metadata{
			ID: "EL-PE-002", Title: "Put an inline policy on its own role",
			Category: SelfEscalation, Severity: Critical, EdgeKind: graph.EdgeModifyPermissions,
			PathfindingIDs:  []string{"iam-005"},
			RequiredActions: []string{"iam:PutRolePolicy"},
			Prerequisites:   []string{"the actor is a role allowed iam:PutRolePolicy on its own ARN"},
			Status:          Stable,
			Attack:          []string{"T1098.003"},
			Remediation:     "Remove iam:PutRolePolicy from the role's policies, or scope its Resource to roles other than itself and add a permissions boundary that denies it.",
			References: []string{
				"https://docs.aws.amazon.com/IAM/latest/APIReference/API_PutRolePolicy.html",
				"https://cwe.mitre.org/data/definitions/269.html",
			},
		},
		kinds:   []graph.NodeKind{graph.NodeRole},
		targets: ownARN,
	}
}
