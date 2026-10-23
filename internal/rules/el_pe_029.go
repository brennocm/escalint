package rules

import "github.com/brennocm/escalint/internal/graph"

// EL-PE-029: run a command on an instance that has a role (pathfinding.cloud ssm-002).
func elPE029() Rule {
	m := Metadata{
		ID: "EL-PE-029", Title: "Run a command on an instance that has a role",
		Category: ExistingPassRole, Severity: High, EdgeKind: graph.EdgeUpdateCode,
		PathfindingIDs:  []string{"ssm-002"},
		RequiredActions: []string{"ssm:SendCommand"},
		Prerequisites:   []string{"an SSM-managed EC2 instance runs with the role"},
		Status:          Experimental,
		Attack:          []string{"T1651", "T1548.005"},
		Remediation:     "Restrict ssm:SendCommand to the resources the caller owns; separate deployment roles from runtime roles.",
		References:      []string{"https://cwe.mitre.org/data/definitions/266.html"},
	}
	return updateCodeRule{meta: m, service: "ec2.amazonaws.com", resources: ssmInstances, noun: "an SSM-managed EC2 instance"}
}
