package rules

import (
	"github.com/brennocm/escalint/internal/graph"
	"github.com/brennocm/escalint/internal/snapshot"
)

// parseRule turns snapshot diagnostics into findings. A policy that could
// not be read contributes nothing to the analysis, so paths that depend on
// it may be missing or conditional: the finding says which policy to fix.
type parseRule struct {
	meta Metadata
	code string
}

func (r parseRule) Meta() Metadata { return r.meta }
func (r parseRule) Pass() Pass     { return PassPrimitive }

func (r parseRule) Apply(ctx *Context) []Finding {
	if r.code == "" {
		return nil // reported outside the rule engine
	}
	var out []Finding
	for _, d := range ctx.Snap.Diagnostics {
		if d.Code != r.code {
			continue
		}
		f := Finding{
			RuleID: r.meta.ID, Severity: r.meta.Severity, Title: r.meta.Title, Message: d.Message,
			Location: Location{Account: d.Account, Entity: d.Entity, Policy: d.Policy, Statement: -1, Path: d.Path},
		}
		if n := ctx.Graph.Node(graph.NodeID(d.Entity)); n != nil {
			f.NodeID = n.ID
		}
		out = append(out, f)
	}
	return out
}

const unmappedParse = "Parser diagnostic about the input, not an adversary behavior."

func elParse001() Rule {
	return parseRule{code: snapshot.CodeParse, meta: Metadata{
		ID: snapshot.CodeParse, Title: "Policy document could not be parsed",
		Category: ParseCategory, Severity: Info, Status: Stable,
		AttackUnmappedReason: unmappedParse,
		Remediation:          "Fix the policy so it is valid IAM JSON (AWS itself rejects most of these documents); until then, paths that depend on it are not analyzed.",
		References:           []string{"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html"},
	}}
}

func elParse002() Rule {
	return parseRule{code: snapshot.CodeUnresolved, meta: Metadata{
		ID: snapshot.CodeUnresolved, Title: "Referenced policy or group is not in the snapshot",
		Category: ParseCategory, Severity: Info, Status: Stable,
		AttackUnmappedReason: unmappedParse,
		Remediation:          "Collect the snapshot again including AWS managed policies (get-account-authorization-details without filters); decisions that depend on the missing policy are conditional.",
		References:           []string{"https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html"},
	}}
}

// elParse003 documents findings about suppressions without a reason; the
// suppress package reports them (they come from .escalint.yaml, not from
// the snapshot), so Apply does nothing.
func elParse003() Rule {
	return parseRule{code: "", meta: Metadata{
		ID: "EL-PARSE-003", Title: "Suppression without a justification",
		Category: ParseCategory, Severity: Info, Status: Stable,
		AttackUnmappedReason: "Configuration diagnostic about .escalint.yaml, not an adversary behavior.",
		Remediation:          "Add a reason to the suppression in .escalint.yaml (who accepted the risk, why, and a ticket), and preferably an expiry date; until then the findings it matches are reported.",
		References:           []string{"https://github.com/brennocm/escalint/blob/main/docs/configuration.md"},
	}}
}
