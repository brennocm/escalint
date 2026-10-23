package rules

import "github.com/brennocm/escalint/internal/graph"

// EL-PE-011: create a console password for another user (pathfinding.cloud iam-004).
func elPE011() Rule {
	m := Metadata{
		ID: "EL-PE-011", Title: "Create a console password for another user",
		Category: PrincipalAccess, Severity: High, EdgeKind: graph.EdgeCredential,
		PathfindingIDs:  []string{"iam-004"},
		RequiredActions: []string{"iam:CreateLoginProfile"},
		Prerequisites:   []string{"the target user has no console password yet"},
		Status:          Stable,
		Attack:          []string{"T1098.001", "T1078.004"},
		Remediation:     "Scope iam:CreateLoginProfile to the caller's own user and require MFA for console access.",
		References:      []string{"https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateLoginProfile.html", "https://cwe.mitre.org/data/definitions/269.html"},
	}
	return pairRule{meta: m, targetKind: graph.NodeUser, actorKinds: iamActors, prereqs: loginProfile(false)}
}
