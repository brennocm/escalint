package eval

import (
	"reflect"
	"strings"
	"testing"

	"github.com/brennocm/escalint/internal/policy"
)

func TestConditionOperators(t *testing.T) {
	ctx := map[string][]string{
		"aws:principalarn":     {"arn:aws:iam::111111111111:role/app/deploy"},
		"aws:principalaccount": {"111111111111"},
		"iam:passedtoservice":  nil, // known absent
		"aws:username":         {"Alice"},
	}
	tests := []struct {
		op, key string
		values  []string
		want    tri
	}{
		{"StringEquals", "aws:PrincipalAccount", []string{"111111111111"}, triTrue},
		{"StringEquals", "aws:PrincipalAccount", []string{"222222222222", "111111111111"}, triTrue}, // values are ORed
		{"StringNotEquals", "aws:PrincipalAccount", []string{"111111111111"}, triFalse},
		{"StringEqualsIgnoreCase", "aws:username", []string{"alice"}, triTrue},
		{"StringEquals", "aws:username", []string{"alice"}, triFalse},
		{"StringNotEqualsIgnoreCase", "aws:username", []string{"ALICE"}, triFalse},
		{"StringLike", "aws:PrincipalArn", []string{"arn:aws:iam::*:role/app/*"}, triTrue},
		{"StringNotLike", "aws:PrincipalArn", []string{"*:role/app/*"}, triFalse},
		{"ArnLike", "aws:PrincipalArn", []string{"arn:aws:iam::111111111111:role/*"}, triTrue},
		{"ArnNotEquals", "aws:PrincipalArn", []string{"arn:aws:iam::111111111111:role/app/deploy"}, triFalse},
		{"Null", "iam:PassedToService", []string{"true"}, triTrue},
		{"Null", "iam:PassedToService", []string{"false"}, triFalse},
		{"Null", "aws:PrincipalAccount", []string{"false"}, triTrue},
		{"StringEquals", "iam:PassedToService", []string{"ec2.amazonaws.com"}, triFalse},
		{"StringEqualsIfExists", "iam:PassedToService", []string{"ec2.amazonaws.com"}, triTrue},
		{"ForAnyValue:StringEquals", "iam:PassedToService", []string{"x"}, triFalse},
		{"ForAllValues:StringEquals", "aws:PrincipalAccount", []string{"111111111111"}, triTrue},
		{"ForAllValues:StringNotEquals", "aws:PrincipalAccount", []string{"111111111111"}, triFalse},
		{"ForAnyValue:StringNotEquals", "aws:PrincipalAccount", []string{"x"}, triTrue},
		{"Bool", "aws:PrincipalAccount", []string{"true"}, triFalse},
		{"NumericLessThan", "aws:PrincipalAccount", []string{"5"}, triUnknown}, // operator not evaluated
		{"NullIfExists", "aws:PrincipalAccount", []string{"true"}, triUnknown}, // invalid combination
		{"StringEquals", "aws:SourceIp", []string{"x"}, triUnknown},            // key not evaluated
		{"StringEquals", "aws:PrincipalOrgID", []string{"o-x"}, triUnknown},    // evaluated key, value unknown
		{"StringEquals", "aws:PrincipalArn", []string{"arn:aws:iam::111111111111:role/${aws:PrincipalTag/x}"}, triUnknown},
	}
	for _, tc := range tests {
		got, _ := evalClause(policy.Clause{Operator: tc.op, Key: tc.key, Values: tc.values}, ctx, policy.Version2012)
		if got != tc.want {
			t.Errorf("%s %s %v = %v, want %v", tc.op, tc.key, tc.values, got, tc.want)
		}
	}
}

func TestConditionIsANDOfClauses(t *testing.T) {
	ctx := map[string][]string{"aws:principalaccount": {"111111111111"}}
	cond := policy.Condition{
		{Operator: "StringEquals", Key: "aws:PrincipalAccount", Values: []string{"111111111111"}},
		{Operator: "Bool", Key: "aws:MultiFactorAuthPresent", Values: []string{"true"}},
	}
	got := evalCondition(cond, ctx, policy.Version2012)
	if got.value != triUnknown || !reflect.DeepEqual(got.keys, []string{"aws:multifactorauthpresent"}) {
		t.Errorf("got %+v", got)
	}
	cond = append(cond, policy.Clause{Operator: "StringEquals", Key: "aws:PrincipalAccount", Values: []string{"222222222222"}})
	if got := evalCondition(cond, ctx, policy.Version2012); got.value != triFalse {
		t.Errorf("a false clause must make the whole condition false, got %+v", got)
	}
}

func TestSubstitute(t *testing.T) {
	ctx := map[string][]string{"aws:username": {"alice"}, "aws:userid": nil}
	tests := []struct {
		in, version, want string
		missing           []string
	}{
		{"arn:aws:s3:::home/${aws:username}/*", policy.Version2012, "arn:aws:s3:::home/alice/*", nil},
		{"arn:aws:s3:::home/${aws:username}/*", policy.Version2008, "arn:aws:s3:::home/${aws:username}/*", nil},
		{"${*}${?}${$}", policy.Version2012, "*?$", nil},
		{"${aws:userid, 'nobody'}", policy.Version2012, "nobody", nil},
		{"${aws:PrincipalTag/team}", policy.Version2012, "", []string{"aws:principaltag/team"}},
		{"unterminated ${aws:username", policy.Version2012, "unterminated ${aws:username", nil},
		{"plain", policy.Version2012, "plain", nil},
	}
	for _, tc := range tests {
		got, missing := substitute(tc.in, ctx, tc.version)
		if len(tc.missing) == 0 && got != tc.want {
			t.Errorf("substitute(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if !reflect.DeepEqual(missing, tc.missing) {
			t.Errorf("substitute(%q) missing = %v, want %v", tc.in, missing, tc.missing)
		}
	}
}

func TestPrincipalGrant(t *testing.T) {
	u := &Principal{Kind: PrincipalUser, ARN: "arn:aws:iam::111111111111:user/alice", ID: "AIDAALICE", Account: "111111111111"}
	svc := &Principal{Kind: PrincipalService, Name: "lambda.amazonaws.com"}
	fed := &Principal{Kind: PrincipalFederated, ARN: "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"}
	ext := &Principal{Kind: PrincipalExternal, Account: "999999999999"}
	anon := &Principal{Kind: PrincipalAnonymous}
	tests := []struct {
		name string
		p    policy.Principal
		pr   *Principal
		want grant
	}{
		{"wildcard", policy.Principal{Wildcard: true}, svc, grantWildcard},
		{"aws wildcard", policy.Principal{AWS: policy.StringList{"*"}}, u, grantWildcard},
		{"aws wildcard does not cover services", policy.Principal{AWS: policy.StringList{"*"}}, svc, grantNone},
		{"account id", policy.Principal{AWS: policy.StringList{"111111111111"}}, u, grantAccount},
		{"account root", policy.Principal{AWS: policy.StringList{"arn:aws:iam::111111111111:root"}}, u, grantAccount},
		{"other account", policy.Principal{AWS: policy.StringList{"222222222222"}}, u, grantNone},
		{"user arn", policy.Principal{AWS: policy.StringList{u.ARN}}, u, grantDirect},
		{"user arn wrong case", policy.Principal{AWS: policy.StringList{strings.ToUpper(u.ARN)}}, u, grantNone},
		{"unique id", policy.Principal{AWS: policy.StringList{"AIDAALICE"}}, u, grantDirect},
		{"best of several", policy.Principal{AWS: policy.StringList{"111111111111", u.ARN}}, u, grantDirect},
		{"session arn is not the user", policy.Principal{AWS: policy.StringList{"arn:aws:sts::111111111111:assumed-role/r/s"}}, u, grantNone},
		{"service", policy.Principal{Service: policy.StringList{"lambda.amazonaws.com"}}, svc, grantDirect},
		{"other service", policy.Principal{Service: policy.StringList{"ec2.amazonaws.com"}}, svc, grantNone},
		{"federated", policy.Principal{Federated: policy.StringList{fed.ARN}}, fed, grantDirect},
		{"external by account", policy.Principal{AWS: policy.StringList{"999999999999"}}, ext, grantAccount},
		{"external by user arn", policy.Principal{AWS: policy.StringList{"arn:aws:iam::999999999999:user/x"}}, ext, grantAccount},
		{"anonymous needs wildcard", policy.Principal{AWS: policy.StringList{"111111111111"}}, anon, grantNone},
		{"canonical user never matches", policy.Principal{CanonicalUser: policy.StringList{"abc"}}, u, grantNone},
		{"malformed arn", policy.Principal{AWS: policy.StringList{"arn:broken"}}, u, grantNone},
	}
	for _, tc := range tests {
		p := tc.p
		if got := principalGrant(&p, tc.pr); got != tc.want {
			t.Errorf("%s: grant = %d, want %d", tc.name, got, tc.want)
		}
	}
	if principalGrant(nil, u) != grantNone {
		t.Error("nil principal element must grant nothing")
	}
}

func TestNotPrincipalAlwaysDeniesPrincipalsWithBoundary(t *testing.T) {
	// reference_policies_elements_notprincipal.html: Deny + NotPrincipal
	// always denies a principal that has a permissions boundary.
	tr := trust(t, `{"Statement":[
		{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:role/caller"},"Action":"sts:AssumeRole"},
		{"Effect":"Deny","NotPrincipal":{"AWS":"arn:aws:iam::111111111111:role/caller"},"Action":"sts:AssumeRole"}]}`)
	r := role(acct, "caller")
	want(t, ask(r, "sts:AssumeRole", roleResource(acct, "target", tr)), Allow)
	r.Boundary = boundaryPolicy(t, allowAll)
	want(t, ask(r, "sts:AssumeRole", roleResource(acct, "target", tr)), ExplicitDeny)
}

func TestServiceAndFederatedPrincipals(t *testing.T) {
	tr := trust(t, `{"Statement":[
		{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"},
		{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"},
		 "Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:example-org/*"}}}]}`)
	res := roleResource(acct, "r", tr)
	got := ask(&Principal{Kind: PrincipalService, Name: "lambda.amazonaws.com"}, "sts:AssumeRole", res)
	want(t, got, Allow)
	if len(got.Notes) == 0 || !strings.Contains(got.Notes[0], "outside the snapshot") {
		t.Errorf("notes = %v", got.Notes)
	}
	want(t, ask(&Principal{Kind: PrincipalService, Name: "ec2.amazonaws.com"}, "sts:AssumeRole", res), ImplicitDeny)
	gh := &Principal{Kind: PrincipalFederated, ARN: "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"}
	fed := ask(gh, "sts:AssumeRoleWithWebIdentity", res)
	want(t, fed, Conditional)
	if !reflect.DeepEqual(fed.Unevaluated, []string{"token.actions.githubusercontent.com:sub"}) {
		t.Errorf("Unevaluated = %v", fed.Unevaluated)
	}
}

func TestUnknownPoliciesMakeDecisionsConditional(t *testing.T) {
	unknown := Policy{Type: TypeIdentity, Source: "arn:aws:iam::aws:policy/ReadOnlyAccess"}
	got := ask(user(acct, "u", unknown), "s3:GetObject", bucket)
	want(t, got, Conditional)
	if !reflect.DeepEqual(got.Unevaluated, []string{unknownPolicyKey}) {
		t.Errorf("Unevaluated = %v", got.Unevaluated)
	}
	// A known allow next to an unknown policy is still only Conditional: the
	// unknown policy might deny.
	got = ask(user(acct, "u", identity(t, allowAll), unknown), "s3:GetObject", bucket)
	want(t, got, Conditional)

	pr := user(acct, "u", identity(t, allowAll))
	pr.Boundary = &Policy{Type: TypeBoundary, Source: "missing-boundary"}
	want(t, ask(pr, "s3:GetObject", bucket), Conditional)

	res := onResource("arn:aws:sts::111111111111:role/x", acct)
	res.RCPsUnknown = true
	want(t, ask(user(acct, "u", identity(t, allowAll)), "sts:AssumeRole", res), Conditional)
}

func TestDecisiveStepsAndTrace(t *testing.T) {
	pr := user(acct, "u", identity(t, `{"Statement":[
		{"Sid":"Reads","Effect":"Allow","Action":"s3:Get*","Resource":"*"},
		{"Sid":"MaybeWrite","Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"true"}}}]}`))
	got := ask(pr, "s3:GetObject", bucket)
	want(t, got, Allow)
	if got.Decisive == nil || got.Decisive.Sid != "Reads" || got.Decisive.Outcome != OutcomeMatch {
		t.Errorf("decisive = %+v", got.Decisive)
	}
	if len(got.Steps) != 2 || got.Steps[1].Outcome != OutcomeConditional {
		t.Errorf("steps = %+v", got.Steps)
	}
	if got.Unevaluated != nil {
		t.Errorf("an unconditional Allow has no unevaluated keys, got %v", got.Unevaluated)
	}

	none := ask(user(acct, "u"), "s3:GetObject", bucket)
	if none.Decision != ImplicitDeny || none.Decisive.Stage != TypeIdentity || none.Decisive.Statement != -1 {
		t.Errorf("implicit deny decisive = %+v", none.Decisive)
	}
	tr := trust(t, `{"Statement":{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}}`)
	noTrust := ask(user(acct, "u", identity(t, allowAll)), "sts:AssumeRole", roleResource(acct, "r", tr))
	if noTrust.Decisive.Stage != TypeResource {
		t.Errorf("missing trust must be the decisive gate, got %+v", noTrust.Decisive)
	}
	rcpRes := onResource("arn:aws:s3:::b/k", acct)
	rcpRes.RCPs = &OrgChain{Levels: [][]Policy{{{Type: TypeRCP, Source: "rcp", Doc: doc(t, policy.KindRCP, `{"Statement":{"Effect":"Allow","Principal":"*","Action":"ec2:*","Resource":"*"}}`)}}}}
	rcpDeny := ask(user(acct, "u", identity(t, allowAll)), "s3:GetObject", rcpRes)
	if rcpDeny.Decision != ImplicitDeny || rcpDeny.Decisive.Stage != TypeRCP {
		t.Errorf("RCP gate = %+v", rcpDeny)
	}
}

func TestNoOrganizationNote(t *testing.T) {
	got := ask(user(acct, "u", identity(t, allowAll)), "s3:GetObject", bucket)
	if len(got.Notes) != 1 || !strings.Contains(got.Notes[0], "SCPs not evaluated") {
		t.Errorf("notes = %v", got.Notes)
	}
}

func TestDecisionString(t *testing.T) {
	for d, s := range map[Decision]string{ExplicitDeny: "ExplicitDeny", ImplicitDeny: "ImplicitDeny", Conditional: "Conditional", Allow: "Allow", Decision(42): "Decision(?)"} {
		if d.String() != s {
			t.Errorf("%d.String() = %q", int(d), d.String())
		}
	}
	if !Allow.Allowed() || !Conditional.Allowed() || ImplicitDeny.Allowed() || ExplicitDeny.Allowed() {
		t.Error("Allowed() wrong")
	}
}

func TestNewContext(t *testing.T) {
	u := user(acct, "alice")
	ctx := NewContext(u, ourOrg)
	if ctx["aws:username"][0] != "alice" || ctx["aws:userid"][0] != "AIDAALICE" || ctx["aws:principalaccount"][0] != acct {
		t.Errorf("user context = %v", ctx)
	}
	if _, known := ctx["aws:principalorgid"]; known {
		t.Error("org ID of an IAM user without OrgID must stay unknown")
	}
	ext := NewContext(&Principal{Kind: PrincipalExternal, Account: external}, ourOrg)
	if ext[orgIDNotKey][0] != ourOrg {
		t.Errorf("external context = %v", ext)
	}
	svc := NewContext(&Principal{Kind: PrincipalService, Name: "ec2.amazonaws.com"}, "")
	if svc["aws:principalisawsservice"][0] != "true" {
		t.Errorf("service context = %v", svc)
	}
	passed := WithPassedToService(ctx, "lambda.amazonaws.com")
	if passed["iam:passedtoservice"][0] != "lambda.amazonaws.com" || ctx["iam:passedtoservice"] != nil {
		t.Error("WithPassedToService must copy, not modify")
	}
}
