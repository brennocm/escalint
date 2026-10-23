package analysis

import (
	"github.com/brennocm/escalint/internal/eval"
	"github.com/brennocm/escalint/internal/graph"
)

// SensitiveReads are the witnesses of Tier 2 sensitive access on every
// resource ("*"), from ADR 0008.
var SensitiveReads = []string{"secretsmanager:GetSecretValue", "kms:Decrypt", "ssm:GetParameter", "ssm:GetParameters", "s3:GetObject"}

// TierInputs are the facts Tier 2 depends on.
type TierInputs struct {
	Finder *CapabilityFinder
	// Primitives are the actions required by registered rules (escalation
	// primitives such as iam:PassRole, ADR 0008 amendment).
	Primitives []string
}

// AssignTiers sets Tier on every node: Tier 0 was set by the graph builder;
// Tier 1 has an enumerated path; Tier 2 has permission management in any
// service, an escalation primitive, or a sensitive read on every resource;
// Tier 3 is the rest. Sinks are Tier 0; principal types outside the snapshot
// stay Tier 3 unless they have a path.
func AssignTiers(g *graph.Graph, paths []Path, in TierInputs) {
	hasPath := map[string]bool{}
	for _, p := range paths {
		hasPath[p.Source] = true
	}
	for _, n := range g.Nodes() {
		switch {
		case n.Kind == graph.NodeTier0Sink:
			n.Tier = 0
		case n.Tier == 0 && (n.Kind == graph.NodeUser || n.Kind == graph.NodeRole || n.Kind == graph.NodeGroup):
			// set by the builder from the probe set
		case hasPath[n.ID]:
			n.Tier = 1
		case tier2(n, in):
			n.Tier = 2
		default:
			n.Tier = 3
		}
	}
}

func tier2(n *graph.Node, in TierInputs) bool {
	if in.Finder == nil || (n.Kind != graph.NodeUser && n.Kind != graph.NodeRole && n.Kind != graph.NodeGroup) {
		return false
	}
	for _, cls := range in.Finder.For(n.ID) {
		if cls == ClassPermissionManagement {
			return true
		}
	}
	pr := in.Finder.Env.Principal(n.ID)
	ctx := eval.NewContext(pr, in.Finder.Env.OrgID)
	for _, a := range in.Primitives {
		if in.Finder.Env.Ask(pr, a, "", "", "", ctx).Decision.Allowed() {
			return true
		}
	}
	for _, a := range SensitiveReads {
		if in.Finder.Env.Ask(pr, a, "*", "", "", ctx).Decision.Allowed() {
			return true
		}
	}
	return false
}
