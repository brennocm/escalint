package rules

import "github.com/brennocm/escalint/internal/graph"

// EL-PE-013: rewrite another role's trust policy and assume it
// (pathfinding.cloud iam-012). After the rewrite the trust names the actor
// directly; the actor's boundary, SCPs and (cross-account) identity policy
// must still allow sts:AssumeRole.
func elPE013() Rule {
	return pairRule{
		meta: Metadata{
			ID: "EL-PE-013", Title: "Rewrite a role's trust policy",
			Category: PrincipalAccess, Severity: High, EdgeKind: graph.EdgeModifyTrust,
			PathfindingIDs:  []string{"iam-012"},
			RequiredActions: []string{"iam:UpdateAssumeRolePolicy"},
			Prerequisites:   []string{"the target role is not service-linked", "the actor can assume the role once the trust names it"},
			Status:          Stable,
			Attack:          []string{"T1098.003"},
			Remediation:     "Restrict iam:UpdateAssumeRolePolicy to administrators, scope it to specific role ARNs, or deny it in a permissions boundary.",
			References: []string{
				"https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateAssumeRolePolicy.html",
				"https://cwe.mitre.org/data/definitions/269.html",
			},
		},
		targetKind: graph.NodeRole,
		actorKinds: []graph.NodeKind{graph.NodeUser, graph.NodeRole},
		prereqs:    notServiceLinked,
		afterwards: canAssumeOnceTrusted,
	}
}
