package rules

import "github.com/brennocm/escalint/internal/graph"

// EL-PE-030: start a build of an existing codebuild project (pathfinding.cloud codebuild-002).
func elPE030() Rule {
	m := Metadata{
		ID: "EL-PE-030", Title: "Start a build of an existing CodeBuild project",
		Category: ExistingPassRole, Severity: High, EdgeKind: graph.EdgeUpdateCode,
		PathfindingIDs:  []string{"codebuild-002"},
		RequiredActions: []string{"codebuild:StartBuild"},
		Prerequisites:   []string{"a CodeBuild project runs with the role"},
		Status:          Experimental,
		Attack:          []string{"T1548.005"},
		Remediation:     "Restrict codebuild:StartBuild to the resources the caller owns; separate deployment roles from runtime roles.",
		References:      []string{"https://cwe.mitre.org/data/definitions/266.html"},
	}
	return updateCodeRule{meta: m, service: "codebuild.amazonaws.com", resources: codeBuildProjects, noun: "a CodeBuild project"}
}
