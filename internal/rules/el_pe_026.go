package rules

import "github.com/brennocm/escalint/internal/graph"

// EL-PE-026: pass a role to a new ecs task (pathfinding.cloud ecs-002, ecs-004).
func elPE026() Rule {
	m := Metadata{
		ID: "EL-PE-026", Title: "Pass a role to a new ECS task",
		Category: NewPassRole, Severity: High, EdgeKind: graph.EdgePassRoleCompute,
		PathfindingIDs:  []string{"ecs-002", "ecs-004"},
		RequiredActions: []string{"iam:PassRole", "ecs:RegisterTaskDefinition", "ecs:RunTask"},
		Prerequisites:   []string{"the role trusts ecs-tasks.amazonaws.com", "an ECS cluster exists or can be created"},
		Status:          Experimental,
		Attack:          []string{"T1548.005"},
		Remediation:     `Scope iam:PassRole to the roles the caller must pass and add "Condition": {"StringEquals": {"iam:PassedToService": "ecs-tasks.amazonaws.com"}} only for those roles.`,
		References:      []string{"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html", "https://cwe.mitre.org/data/definitions/266.html"},
	}
	return passRoleRule{meta: m, service: "ecs-tasks.amazonaws.com", prereqs: clusterExists}
}
