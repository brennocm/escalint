package rules

import "github.com/brennocm/escalint/internal/graph"

// EL-PE-024: pass a role to a new codebuild project (pathfinding.cloud codebuild-001).
func elPE024() Rule {
	m := Metadata{
		ID: "EL-PE-024", Title: "Pass a role to a new CodeBuild project",
		Category: NewPassRole, Severity: High, EdgeKind: graph.EdgePassRoleCompute,
		PathfindingIDs:  []string{"codebuild-001"},
		RequiredActions: []string{"iam:PassRole", "codebuild:CreateProject", "codebuild:StartBuild"},
		Prerequisites:   []string{"the role trusts codebuild.amazonaws.com"},
		Status:          Stable,
		Attack:          []string{"T1548.005"},
		Remediation:     `Scope iam:PassRole to the roles the caller must pass and add "Condition": {"StringEquals": {"iam:PassedToService": "codebuild.amazonaws.com"}} only for those roles.`,
		References:      []string{"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html", "https://cwe.mitre.org/data/definitions/266.html"},
	}
	return passRoleRule{meta: m, service: "codebuild.amazonaws.com"}
}
