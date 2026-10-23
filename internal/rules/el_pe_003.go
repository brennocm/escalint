package rules

import "github.com/brennocm/escalint/internal/graph"

// EL-PE-003: a user adds an inline policy to itself (pathfinding.cloud iam-007).
func elPE003() Rule {
	return selfRule{
		meta: Metadata{
			ID: "EL-PE-003", Title: "Put an inline policy on its own user",
			Category: SelfEscalation, Severity: Critical, EdgeKind: graph.EdgeModifyPermissions,
			PathfindingIDs:  []string{"iam-007"},
			RequiredActions: []string{"iam:PutUserPolicy"},
			Prerequisites:   []string{"the actor is a user allowed iam:PutUserPolicy on its own ARN"},
			Status:          Stable,
			Attack:          []string{"T1098.003"},
			Remediation:     "Remove iam:PutUserPolicy, or limit it with Resource and a permissions boundary so users cannot target themselves.",
			References: []string{
				"https://docs.aws.amazon.com/IAM/latest/APIReference/API_PutUserPolicy.html",
				"https://cwe.mitre.org/data/definitions/269.html",
			},
		},
		kinds:   []graph.NodeKind{graph.NodeUser},
		targets: ownARN,
	}
}
