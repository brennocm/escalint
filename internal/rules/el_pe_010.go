package rules

import "github.com/brennocm/escalint/internal/graph"

// EL-PE-010: create (after deleting one if needed) an access key for
// another user (pathfinding.cloud iam-003). DeleteAccessKey removes the
// two-key limit, so no prerequisite is needed.
func elPE010() Rule {
	return pairRule{
		meta: Metadata{
			ID: "EL-PE-010", Title: "Rotate out and create an access key for another user",
			Category: PrincipalAccess, Severity: High, EdgeKind: graph.EdgeCredential,
			PathfindingIDs:  []string{"iam-003"},
			RequiredActions: []string{"iam:CreateAccessKey", "iam:DeleteAccessKey"},
			Prerequisites:   []string{"the target is an IAM user"},
			Status:          Stable,
			Attack:          []string{"T1098.001", "T1078.004"},
			Remediation:     "Scope iam:CreateAccessKey and iam:DeleteAccessKey to the caller's own user (arn:aws:iam::<account>:user/${aws:username}).",
			References: []string{
				"https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateAccessKey.html",
				"https://cwe.mitre.org/data/definitions/269.html",
			},
		},
		targetKind: graph.NodeUser,
		actorKinds: iamActors,
	}
}
