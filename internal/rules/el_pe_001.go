package rules

import "github.com/brennocm/escalint/internal/graph"

// EL-PE-001: create a new default version of an attached policy (pathfinding.cloud iam-001).
func elPE001() Rule {
	m := Metadata{
		ID: "EL-PE-001", Title: "Create a new default version of an attached policy",
		Category: SelfEscalation, Severity: Critical, EdgeKind: graph.EdgeModifyPermissions,
		PathfindingIDs:  []string{"iam-001"},
		RequiredActions: []string{"iam:CreatePolicyVersion"},
		Prerequisites:   []string{"a customer managed policy is attached to the actor (directly or through a group)"},
		Status:          Stable,
		Attack:          []string{"T1098.003"},
		Remediation:     "Remove iam:CreatePolicyVersion or scope it to policies that are not attached to the caller; deny it in a permissions boundary.",
		References:      []string{"https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreatePolicyVersion.html", "https://cwe.mitre.org/data/definitions/269.html"},
	}
	return selfRule{meta: m, kinds: iamActors, targets: attachedCustomerPolicies}
}
