package rules

import "github.com/brennocm/escalint/internal/graph"

// EL-PE-021: pass a role to a new ec2 instance (pathfinding.cloud ec2-001).
func elPE021() Rule {
	m := Metadata{
		ID: "EL-PE-021", Title: "Pass a role to a new EC2 instance",
		Category: NewPassRole, Severity: High, EdgeKind: graph.EdgePassRoleCompute,
		PathfindingIDs:  []string{"ec2-001"},
		RequiredActions: []string{"iam:PassRole", "ec2:RunInstances"},
		Prerequisites:   []string{"the role trusts ec2.amazonaws.com", "the role is in an instance profile"},
		Status:          Stable,
		Attack:          []string{"T1548.005"},
		Remediation:     `Scope iam:PassRole to the roles the caller must pass and add "Condition": {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}} only for those roles.`,
		References:      []string{"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html", "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_RunInstances.html", "https://cwe.mitre.org/data/definitions/266.html"},
	}
	return passRoleRule{meta: m, service: "ec2.amazonaws.com", prereqs: inInstanceProfile}
}
