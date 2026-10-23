package rules

import "github.com/brennocm/escalint/internal/graph"

// EL-PE-025: pass a role to a new glue job (pathfinding.cloud glue-003).
func elPE025() Rule {
	m := Metadata{
		ID: "EL-PE-025", Title: "Pass a role to a new Glue job",
		Category: NewPassRole, Severity: High, EdgeKind: graph.EdgePassRoleCompute,
		PathfindingIDs:  []string{"glue-003"},
		RequiredActions: []string{"iam:PassRole", "glue:CreateJob", "glue:StartJobRun"},
		Prerequisites:   []string{"the role trusts glue.amazonaws.com"},
		Status:          Stable,
		Attack:          []string{"T1548.005"},
		Remediation:     `Scope iam:PassRole to the roles the caller must pass and add "Condition": {"StringEquals": {"iam:PassedToService": "glue.amazonaws.com"}} only for those roles.`,
		References:      []string{"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html", "https://cwe.mitre.org/data/definitions/266.html"},
	}
	return passRoleRule{meta: m, service: "glue.amazonaws.com"}
}
