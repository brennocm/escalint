package rules

import "github.com/brennocm/escalint/internal/graph"

// EL-PE-009: create an access key for another user (pathfinding.cloud iam-002).
func elPE009() Rule {
	m := Metadata{
		ID: "EL-PE-009", Title: "Create an access key for another user",
		Category: PrincipalAccess, Severity: High, EdgeKind: graph.EdgeCredential,
		PathfindingIDs:  []string{"iam-002"},
		RequiredActions: []string{"iam:CreateAccessKey"},
		Prerequisites:   []string{"the target user has fewer than 2 access keys"},
		Status:          Stable,
		Attack:          []string{"T1098.001", "T1078.004"},
		Remediation:     "Scope iam:CreateAccessKey to the caller's own user (arn:aws:iam::<account>:user/${aws:username}).",
		References:      []string{"https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateAccessKey.html", "https://cwe.mitre.org/data/definitions/269.html"},
	}
	return pairRule{meta: m, targetKind: graph.NodeUser, actorKinds: iamActors, prereqs: keyCountBelowTwo}
}
