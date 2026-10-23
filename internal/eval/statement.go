package eval

import (
	"strings"

	"github.com/brennocm/escalint/internal/arn"
	"github.com/brennocm/escalint/internal/match"
	"github.com/brennocm/escalint/internal/policy"
)

// grant is how a resource-based policy names the principal. It decides what
// else must allow the request in the same account (docs/research.md §2.4).
type grant int

// Grants, from least to most permissive.
const (
	grantNone     grant = iota
	grantAccount        // account ID or :root — the account's identity policies must also allow
	grantDirect         // the principal's own ARN or unique ID
	grantWildcard       // "*" — no identity allow needed in the same account, boundary ignored
)

// principalGrant returns how p names the principal of the request.
func principalGrant(p *policy.Principal, pr *Principal) grant {
	if p == nil {
		return grantNone
	}
	if p.Wildcard {
		return grantWildcard
	}
	best := grantNone
	consider := func(g grant) {
		if g > best {
			best = g
		}
	}
	isAWS := pr.Kind == PrincipalUser || pr.Kind == PrincipalRole || pr.Kind == PrincipalExternal || pr.Kind == PrincipalAnonymous
	for _, entry := range p.AWS {
		if !isAWS {
			break
		}
		consider(awsEntryGrant(entry, pr))
	}
	if pr.Kind == PrincipalService {
		for _, s := range p.Service {
			if s == pr.Name {
				consider(grantDirect)
			}
		}
	}
	if pr.Kind == PrincipalFederated {
		for _, f := range p.Federated {
			if f == pr.ARN || (pr.Name != "" && f == pr.Name) {
				consider(grantDirect)
			}
		}
	}
	return best
}

func awsEntryGrant(entry string, pr *Principal) grant {
	if entry == "*" {
		return grantWildcard
	}
	if pr.Kind == PrincipalAnonymous {
		return grantNone // only "*" names everyone
	}
	if arn.IsAccountID(entry) {
		if entry == pr.Account {
			return grantAccount
		}
		return grantNone
	}
	if !strings.HasPrefix(entry, "arn:") {
		// A unique principal ID (AIDA…, AROA…): IAM stores these in trust
		// policies; a deleted principal's ID matches nothing (E20).
		if pr.ID != "" && entry == pr.ID {
			return grantDirect
		}
		return grantNone
	}
	if strings.ContainsAny(entry, "*?") {
		return grantNone // partial wildcards are not valid in Principal (E21)
	}
	a, err := arn.Parse(entry)
	if err != nil {
		return grantNone
	}
	if a.Service == "iam" && a.Resource == "root" {
		if a.Account == pr.Account {
			return grantAccount
		}
		return grantNone
	}
	if pr.Kind == PrincipalExternal {
		// An external pseudo-principal stands for any principal of its
		// account, including one named explicitly.
		if a.Account == pr.Account {
			return grantAccount
		}
		return grantNone
	}
	if entry == pr.ARN {
		return grantDirect
	}
	return grantNone
}

// stmtResult is how one statement relates to a request.
type stmtResult struct {
	applies tri
	keys    []string
	grant   grant // for statements of resource-based policies
}

// evalStatement checks action, resource, principal and condition.
func evalStatement(st *policy.Statement, req *Request, version string, pt PolicyType) stmtResult {
	patterns, negated := st.Actions()
	matched := false
	for _, p := range patterns {
		if match.Action(p, req.Action) {
			matched = true
			break
		}
	}
	if matched == negated {
		return stmtResult{applies: triFalse}
	}

	var keys []string
	resTri := triTrue
	if req.Resource.ARN == "" && (st.Resource != nil || st.NotResource != nil) {
		// "Any resource" mode (Resource.ARN empty): is the action possible on
		// some resource? An Allow counts if it names any resource; a Deny only
		// removes the capability when it covers every resource.
		resTri = anyResource(st)
		if resTri == triFalse {
			return stmtResult{applies: triFalse}
		}
	} else if st.Resource != nil || st.NotResource != nil {
		list, neg := st.Resource, false
		if st.NotResource != nil {
			list, neg = st.NotResource, true
		}
		found := triFalse
		for _, pattern := range list {
			p, missing := substitute(pattern, req.Context, version)
			if len(missing) > 0 {
				found = maxTri(found, triUnknown)
				keys = append(keys, missing...)
				continue
			}
			if match.ARN(p, req.Resource.ARN) {
				found = triTrue
				break
			}
		}
		resTri = found
		if neg {
			resTri = not(found)
		}
		if resTri == triFalse {
			return stmtResult{applies: triFalse}
		}
	}

	g := grantNone
	if st.Principal != nil || st.NotPrincipal != nil {
		if st.Principal != nil {
			g = principalGrant(st.Principal, req.Principal)
			if g == grantNone {
				return stmtResult{applies: triFalse}
			}
		} else {
			// NotPrincipal (always with Deny): applies to everyone not named.
			// AWS documents that it always denies principals that have a
			// permissions boundary, whatever the list says.
			named := principalGrant(st.NotPrincipal, req.Principal) != grantNone
			if named && req.Principal.Boundary == nil {
				return stmtResult{applies: triFalse}
			}
		}
	} else if pt == TypeResource {
		return stmtResult{applies: triFalse}
	}

	c := evalCondition(st.Condition, req.Context, version)
	applies := and(resTri, c.value)
	if applies == triUnknown {
		keys = append(keys, c.keys...)
	}
	return stmtResult{applies: applies, keys: dedupe(keys), grant: g}
}

func anyResource(st *policy.Statement) tri {
	coversAll := func(list policy.StringList) bool {
		for _, r := range list {
			if r == "*" {
				return true
			}
		}
		return false
	}
	if st.Effect == policy.Allow {
		if st.NotResource != nil && coversAll(st.NotResource) {
			return triFalse // "everything except everything"
		}
		return triTrue
	}
	if st.Resource != nil && coversAll(st.Resource) {
		return triTrue
	}
	return triFalse
}

func maxTri(a, b tri) tri {
	if a > b {
		return a
	}
	return b
}

func not(t tri) tri {
	switch t {
	case triTrue:
		return triFalse
	case triFalse:
		return triTrue
	case triUnknown:
		return triUnknown
	}
	return triUnknown
}

func dedupe(keys []string) []string {
	if len(keys) == 0 {
		return nil
	}
	set := map[string]bool{}
	for _, k := range keys {
		set[k] = true
	}
	return sortedSet(set)
}
