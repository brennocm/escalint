package eval

import (
	"sort"
	"strings"

	"github.com/brennocm/escalint/internal/policy"
)

// unknownPolicyKey marks decisions that depend on a policy whose content is
// not known (not collected or not parsable).
const unknownPolicyKey = "escalint:unknown-policy"

// stageResult aggregates the statements of a set of policies.
type stageResult struct {
	deny, allow tri
	firstDeny   *Step // first statement that denies unconditionally
	firstAllow  *Step // first statement that allows unconditionally
	// byGrant[g] is the allow outcome of the statements that name the
	// principal with grant g (resource-based policies only). Different grants
	// need different extra checks, so they are kept apart.
	byGrant [grantWildcard + 1]tri
	steps   []Step
}

func evalStage(policies []Policy, stage PolicyType, level int, req *Request) stageResult {
	r := stageResult{deny: triFalse, allow: triFalse}
	denyIdx, allowIdx := -1, -1
	for _, p := range policies {
		if p.Doc == nil {
			r.steps = append(r.steps, Step{
				Stage: stage, Policy: p.Source, Name: p.Name, Statement: -1,
				Outcome: OutcomeUnknown, Keys: []string{unknownPolicyKey}, Level: level,
			})
			r.deny = maxTri(r.deny, triUnknown)
			r.allow = maxTri(r.allow, triUnknown)
			continue
		}
		for i := range p.Doc.Statements {
			st := &p.Doc.Statements[i]
			res := evalStatement(st, req, p.Doc.Version, stage)
			if res.applies == triFalse {
				continue
			}
			step := Step{
				Stage: stage, Policy: p.Source, Name: p.Name, Statement: st.Index, Sid: st.Sid,
				Effect: st.Effect, Outcome: OutcomeMatch, Keys: res.keys, Level: level,
			}
			if res.applies == triUnknown {
				step.Outcome = OutcomeConditional
			}
			r.steps = append(r.steps, step)
			if st.Effect == policy.Deny {
				if res.applies == triTrue && denyIdx < 0 {
					denyIdx = len(r.steps) - 1
				}
				r.deny = maxTri(r.deny, res.applies)
				continue
			}
			if res.applies == triTrue && allowIdx < 0 {
				allowIdx = len(r.steps) - 1
			}
			r.allow = maxTri(r.allow, res.applies)
			r.byGrant[res.grant] = maxTri(r.byGrant[res.grant], res.applies)
		}
	}
	r.firstDeny = stepAt(r.steps, denyIdx)
	r.firstAllow = stepAt(r.steps, allowIdx)
	return r
}

// stepAt returns a copy of steps[i], or nil for i < 0.
func stepAt(steps []Step, i int) *Step {
	if i < 0 {
		return nil
	}
	s := steps[i]
	return &s
}

// chainResult evaluates an SCP or RCP chain: a deny at any level denies, and
// every level needs an allow.
type chainResult struct {
	deny, allow tri
	firstDeny   *Step
	failedLevel int // first level whose allow is false, -1 if none
	steps       []Step
}

func evalChain(chain *OrgChain, stage PolicyType, req *Request) chainResult {
	r := chainResult{deny: triFalse, allow: triTrue, failedLevel: -1}
	for level, policies := range chain.Levels {
		s := evalStage(policies, stage, level, req)
		r.steps = append(r.steps, s.steps...)
		if s.deny == triTrue && r.firstDeny == nil {
			r.firstDeny = s.firstDeny
		}
		r.deny = maxTri(r.deny, s.deny)
		if s.allow == triFalse && r.failedLevel < 0 {
			r.failedLevel = level
		}
		r.allow = and(r.allow, s.allow)
	}
	return r
}

// Evaluate decides the request. See the package documentation and
// docs/research.md §2 for the rules applied.
func Evaluate(req *Request) Result {
	pr, res := req.Principal, req.Resource
	var out Result
	note := func(s string) { out.Notes = append(out.Notes, s) }

	// The caller side is only known for IAM users and roles in the snapshot.
	callerKnown := pr.Kind == PrincipalUser || pr.Kind == PrincipalRole
	if !callerKnown {
		note("caller-side policies are outside the snapshot and assumed to allow")
	}

	// A role can only be passed to a service in its own account (E33).
	if strings.EqualFold(req.Action, "iam:PassRole") && res.Account != "" && pr.Account != "" && res.Account != pr.Account {
		out.Decision = ImplicitDeny
		out.Decisive = &Step{Stage: TypeIdentity, Policy: "passrole-same-account", Statement: -1}
		note("iam:PassRole only works for roles in the caller's own account")
		return out
	}

	// --- Collect every stage (order: RCP, SCP, resource, identity, boundary).
	rcp := chainResult{deny: triFalse, allow: triTrue, failedLevel: -1}
	switch {
	case res.RCPsUnknown && !pr.ServiceLinked:
		rcp.allow = triUnknown
		rcp.steps = append(rcp.steps, Step{Stage: TypeRCP, Policy: "rcp", Statement: -1, Outcome: OutcomeUnknown, Keys: []string{unknownPolicyKey}})
		note("RCPs apply but were not collected")
	case res.RCPs != nil && !pr.ServiceLinked:
		rcp = evalChain(res.RCPs, TypeRCP, req)
	}

	scp := chainResult{deny: triFalse, allow: triTrue, failedLevel: -1}
	switch {
	case !callerKnown:
	case pr.SCPsUnknown && !pr.ServiceLinked:
		scp.allow = triUnknown
		scp.steps = append(scp.steps, Step{Stage: TypeSCP, Policy: "scp", Statement: -1, Outcome: OutcomeUnknown, Keys: []string{unknownPolicyKey}})
		note("the account is in an organization whose SCPs were not collected")
	case pr.SCPs != nil && !pr.ServiceLinked:
		scp = evalChain(pr.SCPs, TypeSCP, req)
	case pr.SCPs == nil && !pr.ServiceLinked:
		note("SCPs not evaluated: no organization data for the account")
	}

	resource := stageResult{deny: triFalse, allow: triFalse}
	if res.Policy != nil {
		resource = evalStage([]Policy{*res.Policy}, TypeResource, 0, req)
	}

	identity := stageResult{deny: triFalse, allow: triTrue}
	boundary := stageResult{deny: triFalse, allow: triTrue}
	if callerKnown {
		identity = evalStage(pr.Identity, TypeIdentity, 0, req)
		if pr.Boundary != nil {
			boundary = evalStage([]Policy{*pr.Boundary}, TypeBoundary, 0, req)
		}
	}

	out.Steps = append(out.Steps, rcp.steps...)
	out.Steps = append(out.Steps, scp.steps...)
	out.Steps = append(out.Steps, resource.steps...)
	out.Steps = append(out.Steps, identity.steps...)
	out.Steps = append(out.Steps, boundary.steps...)

	// --- 1. Explicit deny in any policy.
	for _, d := range []*Step{rcp.firstDeny, scp.firstDeny, resource.firstDeny, identity.firstDeny, boundary.firstDeny} {
		if d != nil {
			out.Decision, out.Decisive = ExplicitDeny, d
			return out
		}
	}
	denyTri := maxTri(maxTri(rcp.deny, scp.deny), maxTri(resource.deny, maxTri(identity.deny, boundary.deny)))

	// --- 2–6. Gates. viaIdentity is the identity-based path; viaResource the
	// path where the resource policy grants access.
	sameAccount := pr.Account != "" && (res.Account == "" || res.Account == pr.Account)
	idAndBoundary := and(identity.allow, boundary.allow)
	var access tri
	var allowStep *Step
	switch {
	case res.Policy == nil:
		access, allowStep = idAndBoundary, identity.firstAllow
	case !callerKnown:
		// Services, federated users, external accounts, anyone: the resource
		// policy (trust) is the only side we can see.
		access, allowStep = resource.allow, resource.firstAllow
	case sameAccount:
		// Each way the trust names the principal has its own requirements;
		// the request is allowed through the best of them.
		direct := resource.byGrant[grantDirect]
		if pr.Kind == PrincipalRole {
			direct = and(direct, boundary.allow) // role ARN grants are limited by the boundary
		}
		viaAccount := and(maxTri(resource.byGrant[grantAccount], resource.byGrant[grantNone]), idAndBoundary)
		access = maxTri(maxTri(resource.byGrant[grantWildcard], direct), viaAccount)
		allowStep = resource.firstAllow
	default: // cross-account: both sides must allow
		access, allowStep = and(resource.allow, idAndBoundary), resource.firstAllow
	}

	final := and(and(rcp.allow, scp.allow), access)
	if final == triTrue && denyTri == triUnknown {
		final = triUnknown // a conditional deny might still apply
	}

	switch final {
	case triTrue:
		out.Decision, out.Decisive = Allow, allowStep
	case triUnknown:
		out.Decision, out.Decisive = Conditional, allowStep
		out.Unevaluated = unevaluated(out.Steps)
	case triFalse:
		out.Decision = ImplicitDeny
		out.Decisive = implicitDenyReason(rcp, scp, res.Policy != nil, resource, identity, callerKnown)
	}
	return out
}

// implicitDenyReason names the first gate that had no allow.
func implicitDenyReason(rcp, scp chainResult, hasResource bool, resource, identity stageResult, callerKnown bool) *Step {
	switch {
	case rcp.allow == triFalse:
		return &Step{Stage: TypeRCP, Policy: "rcp", Statement: -1, Level: rcp.failedLevel}
	case scp.allow == triFalse:
		return &Step{Stage: TypeSCP, Policy: "scp", Statement: -1, Level: scp.failedLevel}
	case hasResource && resource.allow == triFalse:
		return &Step{Stage: TypeResource, Policy: "resource", Statement: -1}
	case callerKnown && identity.allow == triFalse:
		return &Step{Stage: TypeIdentity, Policy: "identity", Statement: -1}
	default: // the remaining gate is the permissions boundary
		return &Step{Stage: TypeBoundary, Policy: "boundary", Statement: -1}
	}
}

func unevaluated(steps []Step) []string {
	set := map[string]bool{}
	for _, s := range steps {
		if s.Outcome == OutcomeConditional || s.Outcome == OutcomeUnknown {
			for _, k := range s.Keys {
				set[k] = true
			}
		}
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
