package rules

import "github.com/brennocm/escalint/internal/graph"

// EL-PE-012: change another user's console password (pathfinding.cloud iam-006).
func elPE012() Rule {
	m := Metadata{
		ID: "EL-PE-012", Title: "Change another user's console password",
		Category: PrincipalAccess, Severity: High, EdgeKind: graph.EdgeCredential,
		PathfindingIDs:  []string{"iam-006"},
		RequiredActions: []string{"iam:UpdateLoginProfile"},
		Prerequisites:   []string{"the target user has a console password", "MFA on the target may still block console use"},
		Status:          Stable,
		Attack:          []string{"T1098.001", "T1078.004"},
		Remediation:     "Scope iam:UpdateLoginProfile to the caller's own user and enforce MFA for every console user.",
		References:      []string{"https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateLoginProfile.html", "https://cwe.mitre.org/data/definitions/269.html"},
	}
	return pairRule{meta: m, targetKind: graph.NodeUser, actorKinds: iamActors, prereqs: loginProfile(true)}
}
