package rules

import "github.com/brennocm/escalint/internal/graph"

// EL-PE-022: pass a role to a new Lambda function and invoke it
// (pathfinding.cloud lambda-001).
func elPE022() Rule {
	return passRoleRule{
		meta: Metadata{
			ID: "EL-PE-022", Title: "Pass a role to a new Lambda function and invoke it",
			Category: NewPassRole, Severity: High, EdgeKind: graph.EdgePassRoleCompute,
			PathfindingIDs:  []string{"lambda-001"},
			RequiredActions: []string{"iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"},
			Prerequisites:   []string{"the role trusts lambda.amazonaws.com"},
			Status:          Stable,
			Attack:          []string{"T1548.005", "T1648"},
			Remediation:     `Scope iam:PassRole to the roles the caller must pass and add "Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}} only for those roles.`,
			References: []string{
				"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html",
				"https://cwe.mitre.org/data/definitions/266.html",
			},
		},
		service: "lambda.amazonaws.com",
	}
}
