package rules

import "github.com/brennocm/escalint/internal/graph"

// EL-PE-028: update the code of an existing lambda function and invoke it (pathfinding.cloud lambda-004).
func elPE028() Rule {
	m := Metadata{
		ID: "EL-PE-028", Title: "Update the code of an existing Lambda function and invoke it",
		Category: ExistingPassRole, Severity: High, EdgeKind: graph.EdgeUpdateCode,
		PathfindingIDs:  []string{"lambda-004"},
		RequiredActions: []string{"lambda:UpdateFunctionCode", "lambda:InvokeFunction"},
		Prerequisites:   []string{"a Lambda function runs with the role"},
		Status:          Stable,
		Attack:          []string{"T1648", "T1548.005"},
		Remediation:     "Restrict lambda:UpdateFunctionCode and lambda:InvokeFunction to the resources the caller owns; separate deployment roles from runtime roles.",
		References:      []string{"https://cwe.mitre.org/data/definitions/266.html"},
	}
	return updateCodeRule{meta: m, service: "lambda.amazonaws.com", resources: lambdaFunctions, noun: "a Lambda function"}
}
