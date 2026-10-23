package rules

import "github.com/brennocm/escalint/internal/graph"

// EL-PE-027: pass a role to a new sagemaker notebook (pathfinding.cloud sagemaker-001).
func elPE027() Rule {
	m := Metadata{
		ID: "EL-PE-027", Title: "Pass a role to a new SageMaker notebook",
		Category: NewPassRole, Severity: High, EdgeKind: graph.EdgePassRoleCompute,
		PathfindingIDs:  []string{"sagemaker-001"},
		RequiredActions: []string{"iam:PassRole", "sagemaker:CreateNotebookInstance"},
		Prerequisites:   []string{"the role trusts sagemaker.amazonaws.com"},
		Status:          Stable,
		Attack:          []string{"T1548.005"},
		Remediation:     `Scope iam:PassRole to the roles the caller must pass and add "Condition": {"StringEquals": {"iam:PassedToService": "sagemaker.amazonaws.com"}} only for those roles.`,
		References:      []string{"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html", "https://cwe.mitre.org/data/definitions/266.html"},
	}
	return passRoleRule{meta: m, service: "sagemaker.amazonaws.com"}
}
