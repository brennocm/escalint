package eval

import "strings"

// orgIDNotKey carries an organization ID the principal is known NOT to
// belong to, when its own organization is unknown (a principal outside the
// analyzed organization). It lets "aws:PrincipalOrgID equals <our org>"
// evaluate to false instead of Conditional.
const orgIDNotKey = "escalint:principalorgid-not"

// NewContext returns the statically known condition keys for a principal.
// Keys that cannot be known are left out, so conditions on them stay
// Conditional. iam:PassedToService is recorded as absent; callers that
// evaluate iam:PassRole set it with WithPassedToService.
//
// ourOrgID is the analyzed organization, or "" when there is no
// organization data.
func NewContext(pr *Principal, ourOrgID string) map[string][]string {
	ctx := map[string][]string{
		"iam:passedtoservice": nil,
	}
	switch pr.Kind {
	case PrincipalUser, PrincipalRole:
		ctx["aws:principalarn"] = []string{pr.ARN}
		ctx["aws:principalaccount"] = []string{pr.Account}
		ctx["aws:principalisawsservice"] = []string{"false"}
		// Groups are evaluated as "a new member" with the group's ARN
		// (graph.Env.addGroup): the member's user name and ID are unknown,
		// so ${aws:username} stays unresolved (Conditional).
		if pr.Kind == PrincipalUser && strings.Contains(pr.ARN, ":user/") {
			name := pr.ARN[strings.LastIndex(pr.ARN, "/")+1:]
			ctx["aws:username"] = []string{name}
			if pr.ID != "" {
				ctx["aws:userid"] = []string{pr.ID}
			}
		}
	case PrincipalService:
		ctx["aws:principalisawsservice"] = []string{"true"}
	case PrincipalExternal:
		ctx["aws:principalaccount"] = []string{pr.Account}
		ctx["aws:principalisawsservice"] = []string{"false"}
	case PrincipalFederated, PrincipalAnonymous:
		ctx["aws:principalisawsservice"] = []string{"false"}
	}
	switch {
	case pr.OrgID != "":
		ctx["aws:principalorgid"] = []string{pr.OrgID}
	case ourOrgID != "" && (pr.Kind == PrincipalExternal || pr.Kind == PrincipalAnonymous):
		ctx[orgIDNotKey] = []string{ourOrgID}
	}
	return ctx
}

// WithPassedToService returns a copy of ctx with iam:PassedToService set.
func WithPassedToService(ctx map[string][]string, service string) map[string][]string {
	out := make(map[string][]string, len(ctx))
	for k, v := range ctx {
		out[k] = v
	}
	out["iam:passedtoservice"] = []string{service}
	return out
}
