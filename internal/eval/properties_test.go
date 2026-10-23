package eval

import (
	"reflect"
	"testing"

	"pgregory.net/rapid"

	"github.com/brennocm/escalint/internal/policy"
)

// A small universe so random policies often overlap with the request.
var (
	propActions   = []string{"*", "s3:*", "s3:Get*", "s3:GetObject", "s3:PutObject", "iam:PassRole", "iam:*"}
	propResources = []string{"*", "arn:aws:s3:::b/*", "arn:aws:s3:::c/*", "arn:aws:iam::111111111111:role/*"}
	propRequests  = []struct{ action, resource string }{
		{"s3:GetObject", "arn:aws:s3:::b/k"},
		{"s3:PutObject", "arn:aws:s3:::c/k"},
		{"iam:PassRole", "arn:aws:iam::111111111111:role/admin"},
	}
)

func genCondition(t *rapid.T, label string) policy.Condition {
	switch rapid.IntRange(0, 3).Draw(t, label) {
	case 1: // request-time key: never evaluated
		return policy.Condition{{Operator: "Bool", Key: "aws:MultiFactorAuthPresent", Values: []string{"true"}}}
	case 2: // statically known: true for our principal
		return policy.Condition{{Operator: "StringEquals", Key: "aws:PrincipalAccount", Values: []string{acct}}}
	case 3: // statically known: false for our principal
		return policy.Condition{{Operator: "StringEquals", Key: "aws:PrincipalAccount", Values: []string{other}}}
	default:
		return nil
	}
}

func genStatement(t *rapid.T, label string, effect policy.Effect) policy.Statement {
	st := policy.Statement{Effect: effect, Condition: genCondition(t, label+".cond")}
	actions := policy.StringList{rapid.SampledFrom(propActions).Draw(t, label+".action")}
	resources := policy.StringList{rapid.SampledFrom(propResources).Draw(t, label+".resource")}
	if rapid.Bool().Draw(t, label+".notAction") {
		st.NotAction = actions
	} else {
		st.Action = actions
	}
	if rapid.Bool().Draw(t, label+".notResource") {
		st.NotResource = resources
	} else {
		st.Resource = resources
	}
	return st
}

func genDoc(t *rapid.T, label string) *policy.Document {
	n := rapid.IntRange(1, 4).Draw(t, label+".n")
	d := &policy.Document{Version: policy.Version2012}
	for i := 0; i < n; i++ {
		effect := policy.Allow
		if rapid.IntRange(0, 3).Draw(t, label+".deny") == 0 {
			effect = policy.Deny
		}
		st := genStatement(t, label, effect)
		st.Index = i
		d.Statements = append(d.Statements, st)
	}
	return d
}

func genPolicies(t *rapid.T, label string, pt PolicyType) []Policy {
	n := rapid.IntRange(0, 3).Draw(t, label+".count")
	out := make([]Policy, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, Policy{Type: pt, Source: label, Doc: genDoc(t, label)})
	}
	return out
}

func genRequest(t *rapid.T) *Request {
	pr := &Principal{Kind: PrincipalUser, ARN: "arn:aws:iam::" + acct + ":user/u", Account: acct, Identity: genPolicies(t, "identity", TypeIdentity)}
	if rapid.Bool().Draw(t, "hasBoundary") {
		b := Policy{Type: TypeBoundary, Source: "boundary", Doc: genDoc(t, "boundary")}
		pr.Boundary = &b
	}
	if rapid.Bool().Draw(t, "hasSCP") {
		pr.SCPs = &OrgChain{Levels: [][]Policy{genPolicies(t, "scp", TypeSCP)}}
	}
	r := rapid.SampledFrom(propRequests).Draw(t, "request")
	return &Request{Principal: pr, Action: r.action, Resource: &Resource{ARN: r.resource, Account: ""}, Context: NewContext(pr, "")}
}

func clone(req *Request) *Request {
	pr := *req.Principal
	pr.Identity = append([]Policy(nil), pr.Identity...)
	c := *req
	c.Principal = &pr
	return &c
}

func TestPropertyDeterministic(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		req := genRequest(t)
		if a, b := Evaluate(req), Evaluate(req); !reflect.DeepEqual(a, b) {
			t.Fatalf("Evaluate is not deterministic:\n%+v\n%+v", a, b)
		}
	})
}

func TestPropertyUnconditionalDenyAlwaysWins(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		req := clone(genRequest(t))
		deny := &policy.Document{Version: policy.Version2012, Statements: []policy.Statement{
			{Effect: policy.Deny, Action: policy.StringList{"*"}, Resource: policy.StringList{"*"}},
		}}
		where := rapid.IntRange(0, 1).Draw(t, "where")
		if where == 0 || req.Principal.Boundary == nil {
			req.Principal.Identity = append(req.Principal.Identity, Policy{Type: TypeIdentity, Source: "deny", Doc: deny})
		} else {
			b := *req.Principal.Boundary
			b.Doc = &policy.Document{Version: policy.Version2012, Statements: append(append([]policy.Statement(nil), b.Doc.Statements...), deny.Statements[0])}
			req.Principal.Boundary = &b
		}
		if got := Evaluate(req).Decision; got != ExplicitDeny {
			t.Fatalf("decision = %s with an unconditional Deny", got)
		}
	})
}

func TestPropertyBoundaryAndSCPNeverGrant(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		req := genRequest(t)
		with := Evaluate(req).Decision

		withoutLimits := clone(req)
		withoutLimits.Principal.Boundary = nil
		withoutLimits.Principal.SCPs = nil
		without := Evaluate(withoutLimits).Decision
		if with > without {
			t.Fatalf("limits granted access: with=%s without=%s", with, without)
		}
	})
}

func TestPropertyAddingDenyNeverGrants(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		req := genRequest(t)
		before := Evaluate(req).Decision
		after := clone(req)
		extra := &policy.Document{Version: policy.Version2012, Statements: []policy.Statement{genStatement(t, "extra", policy.Deny)}}
		after.Principal.Identity = append(after.Principal.Identity, Policy{Type: TypeIdentity, Source: "extra", Doc: extra})
		if got := Evaluate(after).Decision; got > before {
			t.Fatalf("adding a Deny raised %s to %s", before, got)
		}
	})
}

func TestPropertyOrderIndependent(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		req := genRequest(t)
		want := Evaluate(req).Decision

		shuffled := clone(req)
		ids := shuffled.Principal.Identity
		perm := rapid.Permutation(ids).Draw(t, "policyOrder")
		for i := range perm {
			d := *perm[i].Doc
			d.Statements = rapid.Permutation(d.Statements).Draw(t, "statementOrder")
			perm[i].Doc = &d
		}
		shuffled.Principal.Identity = perm
		if got := Evaluate(shuffled).Decision; got != want {
			t.Fatalf("order changed the decision: %s -> %s", want, got)
		}
	})
}
