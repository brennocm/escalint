package rules

import "github.com/brennocm/escalint/internal/graph"

// EL-PE-023: pass a role to a new cloudformation stack (pathfinding.cloud cloudformation-001).
func elPE023() Rule {
	m := Metadata{
		ID: "EL-PE-023", Title: "Pass a role to a new CloudFormation stack",
		Category: NewPassRole, Severity: High, EdgeKind: graph.EdgePassRoleCompute,
		PathfindingIDs:  []string{"cloudformation-001"},
		RequiredActions: []string{"iam:PassRole", "cloudformation:CreateStack"},
		Prerequisites:   []string{"the role trusts cloudformation.amazonaws.com"},
		Status:          Stable,
		Attack:          []string{"T1548.005"},
		Remediation:     `Scope iam:PassRole to the roles the caller must pass and add "Condition": {"StringEquals": {"iam:PassedToService": "cloudformation.amazonaws.com"}} only for those roles.`,
		References:      []string{"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html", "https://cwe.mitre.org/data/definitions/266.html"},
	}
	return passRoleRule{meta: m, service: "cloudformation.amazonaws.com"}
}
