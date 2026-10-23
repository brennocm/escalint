package eval

// One test per row of the edge-case table in docs/research.md §3. Each name
// carries the case number and the documentation page it comes from.

import (
	"strings"
	"testing"

	"github.com/brennocm/escalint/internal/policy"
)

const (
	acct     = "111111111111"
	other    = "222222222222"
	external = "999999999999"
	ourOrg   = "o-exampleorg1"
)

func doc(t *testing.T, kind policy.Kind, text string) *policy.Document {
	t.Helper()
	d, err := policy.Parse([]byte(text), kind, policy.Limits{})
	if err != nil {
		t.Fatalf("policy.Parse(%s) error = %v", text, err)
	}
	return d
}

func identity(t *testing.T, text string) Policy {
	return Policy{Type: TypeIdentity, Source: "test-identity", Doc: doc(t, policy.KindIdentity, text)}
}

func boundaryPolicy(t *testing.T, text string) *Policy {
	return &Policy{Type: TypeBoundary, Source: "test-boundary", Doc: doc(t, policy.KindIdentity, text)}
}

func trust(t *testing.T, text string) *Policy {
	return &Policy{Type: TypeResource, Source: "test-trust", Doc: doc(t, policy.KindResource, text)}
}

func scpChain(t *testing.T, levels ...string) *OrgChain {
	c := &OrgChain{}
	for i, l := range levels {
		c.Levels = append(c.Levels, []Policy{{Type: TypeSCP, Source: "scp-" + string(rune('0'+i)), Doc: doc(t, policy.KindSCP, l)}})
	}
	return c
}

func user(account, name string, policies ...Policy) *Principal {
	return &Principal{
		Kind: PrincipalUser, ARN: "arn:aws:iam::" + account + ":user/" + name,
		ID: "AIDA" + strings.ToUpper(name), Account: account, Identity: policies,
	}
}

func role(account, name string, policies ...Policy) *Principal {
	return &Principal{
		Kind: PrincipalRole, ARN: "arn:aws:iam::" + account + ":role/" + name,
		ID: "AROA" + strings.ToUpper(name), Account: account, Identity: policies,
	}
}

func onResource(arn, account string) *Resource {
	return &Resource{ARN: arn, Account: account}
}

func ask(pr *Principal, action string, res *Resource) Result {
	return Evaluate(&Request{Principal: pr, Action: action, Resource: res, Context: NewContext(pr, ourOrg)})
}

func roleResource(account, name string, tr *Policy) *Resource {
	return &Resource{ARN: "arn:aws:iam::" + account + ":role/" + name, Account: account, Policy: tr}
}

func want(t *testing.T, got Result, d Decision) {
	t.Helper()
	if got.Decision != d {
		t.Fatalf("decision = %s, want %s (decisive %+v, notes %v)", got.Decision, d, got.Decisive, got.Notes)
	}
}

const allowAll = `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`

var bucket = onResource("arn:aws:s3:::example-bucket/key", "")

// docs: reference_policies_elements_notaction.html
func TestE01NotActionAllowGrantsOtherServices(t *testing.T) {
	p := identity(t, `{"Statement":{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}}`)
	want(t, ask(user(acct, "u", p), "s3:GetObject", bucket), Allow)
}

func TestE02NotActionAllowExcludesListedService(t *testing.T) {
	p := identity(t, `{"Statement":{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}}`)
	want(t, ask(user(acct, "u", p), "iam:PutUserPolicy", onResource("arn:aws:iam::"+acct+":user/u", acct)), ImplicitDeny)
}

func TestE03NotActionScopedByResource(t *testing.T) {
	p := identity(t, `{"Statement":{"Effect":"Allow","NotAction":"iam:*","Resource":"arn:aws:s3:::*"}}`)
	want(t, ask(user(acct, "u", p), "ec2:RunInstances", onResource("arn:aws:ec2:us-east-1:"+acct+":instance/*", acct)), ImplicitDeny)
}

func TestE04NotActionDenyDoesNotDenyListedActions(t *testing.T) {
	pr := user(acct, "u",
		identity(t, allowAll),
		identity(t, `{"Statement":{"Effect":"Deny","NotAction":"iam:*","Resource":"*"}}`))
	want(t, ask(pr, "iam:ListUsers", onResource("*", "")), Allow)
	want(t, ask(pr, "s3:GetObject", bucket), ExplicitDeny)
}

// docs: reference_policies_evaluation-logic_policy-eval-denyallow.html
func TestE05BoundaryLimitsIdentity(t *testing.T) {
	pr := user(acct, "u", identity(t, `{"Statement":{"Effect":"Allow","Action":"iam:*","Resource":"*"}}`))
	pr.Boundary = boundaryPolicy(t, `{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`)
	got := ask(pr, "iam:PutRolePolicy", onResource("arn:aws:iam::"+acct+":role/r", acct))
	want(t, got, ImplicitDeny)
	if got.Decisive.Stage != TypeBoundary {
		t.Errorf("decisive stage = %s, want boundary", got.Decisive.Stage)
	}
}

func TestE06DenyInBoundaryIsExplicit(t *testing.T) {
	pr := user(acct, "u", identity(t, allowAll))
	pr.Boundary = boundaryPolicy(t, `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"iam:*","Resource":"*"}]}`)
	got := ask(pr, "iam:CreateAccessKey", onResource("arn:aws:iam::"+acct+":user/u", acct))
	want(t, got, ExplicitDeny)
	if got.Decisive.Stage != TypeBoundary || got.Decisive.Statement != 1 {
		t.Errorf("decisive = %+v", got.Decisive)
	}
}

// docs: organizations/latest/userguide/orgs_manage_policies_scps_evaluation.html
func TestE07SCPNeedsAllowAtEveryLevel(t *testing.T) {
	pr := user(acct, "u", identity(t, allowAll))
	pr.SCPs = scpChain(t, allowAll, `{"Statement":{"Effect":"Allow","Action":"ec2:*","Resource":"*"}}`)
	got := ask(pr, "iam:CreateAccessKey", onResource("arn:aws:iam::"+acct+":user/u", acct))
	want(t, got, ImplicitDeny)
	if got.Decisive.Stage != TypeSCP || got.Decisive.Level != 1 {
		t.Errorf("decisive = %+v, want SCP level 1", got.Decisive)
	}
	want(t, ask(pr, "ec2:RunInstances", onResource("*", "")), Allow)
}

// docs: orgs_manage_policies_scps.html — the graph builder leaves SCPs nil for
// principals of the management account; the evaluator then allows.
func TestE08ManagementAccountIgnoresSCPs(t *testing.T) {
	pr := user(acct, "u", identity(t, allowAll))
	pr.SCPs = nil
	got := ask(pr, "iam:CreateAccessKey", onResource("arn:aws:iam::"+acct+":user/u", acct))
	want(t, got, Allow)
}

func TestE09ServiceLinkedRoleIgnoresSCPs(t *testing.T) {
	pr := role(acct, "AWSServiceRoleForX", identity(t, allowAll))
	pr.ServiceLinked = true
	pr.SCPs = scpChain(t, `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"iam:*","Resource":"*"}]}`)
	want(t, ask(pr, "iam:CreateRole", onResource("*", "")), Allow)
}

// docs: orgs_manage_policies_rcps.html
func TestE10RCPDeniesExternalAssumeRole(t *testing.T) {
	tr := trust(t, `{"Statement":{"Effect":"Allow","Principal":{"AWS":"`+external+`"},"Action":"sts:AssumeRole"}}`)
	res := roleResource(acct, "r", tr)
	res.RCPs = &OrgChain{Levels: [][]Policy{{{Type: TypeRCP, Source: "rcp", Doc: doc(t, policy.KindRCP, `{"Statement":[
		{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"},
		{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole","Resource":"*","Condition":{"StringNotEquals":{"aws:PrincipalOrgID":"`+ourOrg+`"}}}]}`)}}}}
	ext := &Principal{Kind: PrincipalExternal, Account: external}
	got := ask(ext, "sts:AssumeRole", res)
	want(t, got, ExplicitDeny)
	if got.Decisive.Stage != TypeRCP {
		t.Errorf("decisive = %+v", got.Decisive)
	}
}

func TestE11RCPsDoNotCoverIAM(t *testing.T) {
	if RCPApplies("iam:PutRolePolicy") {
		t.Error("RCPApplies(iam:PutRolePolicy) = true; IAM is not an RCP service")
	}
	if !RCPApplies("sts:AssumeRole") || !RCPApplies("S3:GetObject") {
		t.Error("RCPApplies must cover sts and s3")
	}
}

// docs: orgs_manage_policies_rcps.html — management-account resources get
// RCPs == nil from the builder.
func TestE12ManagementAccountResourcesIgnoreRCPs(t *testing.T) {
	tr := trust(t, `{"Statement":{"Effect":"Allow","Principal":{"AWS":"`+external+`"},"Action":"sts:AssumeRole"}}`)
	want(t, ask(&Principal{Kind: PrincipalExternal, Account: external}, "sts:AssumeRole", roleResource(acct, "r", tr)), Allow)
}

// docs: STS/latest/APIReference/API_AssumeRole.html
func TestE13TrustNamingUserNeedsNoIdentityPolicy(t *testing.T) {
	u := user(acct, "alice")
	tr := trust(t, `{"Statement":{"Effect":"Allow","Principal":{"AWS":"`+u.ARN+`"},"Action":"sts:AssumeRole"}}`)
	want(t, ask(u, "sts:AssumeRole", roleResource(acct, "r", tr)), Allow)
}

// docs: reference_policies_evaluation-logic_policy-eval-denyallow.html
func TestE14TrustNamingRoleIsLimitedByBoundary(t *testing.T) {
	r := role(acct, "caller")
	r.Boundary = boundaryPolicy(t, `{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`)
	tr := trust(t, `{"Statement":{"Effect":"Allow","Principal":{"AWS":"`+r.ARN+`"},"Action":"sts:AssumeRole"}}`)
	want(t, ask(r, "sts:AssumeRole", roleResource(acct, "target", tr)), ImplicitDeny)
}

func TestE15TrustNamingRoleNeedsNoIdentityPolicy(t *testing.T) {
	r := role(acct, "caller")
	tr := trust(t, `{"Statement":{"Effect":"Allow","Principal":{"AWS":"`+r.ARN+`"},"Action":"sts:AssumeRole"}}`)
	want(t, ask(r, "sts:AssumeRole", roleResource(acct, "target", tr)), Allow)
}

// docs: STS/latest/APIReference/API_AssumeRole.html
func TestE16TrustNamingAccountNeedsIdentityPolicy(t *testing.T) {
	tr := trust(t, `{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::`+acct+`:root"},"Action":"sts:AssumeRole"}}`)
	res := roleResource(acct, "r", tr)
	want(t, ask(user(acct, "u"), "sts:AssumeRole", res), ImplicitDeny)
	allowAssume := identity(t, `{"Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"arn:aws:iam::`+acct+`:role/r"}}`)
	want(t, ask(user(acct, "u", allowAssume), "sts:AssumeRole", res), Allow)
}

// docs: reference_policies_evaluation-logic-cross-account.html
func TestE17CrossAccountNeedsBothSides(t *testing.T) {
	u := user(other, "bob")
	tr := trust(t, `{"Statement":{"Effect":"Allow","Principal":{"AWS":"`+u.ARN+`"},"Action":"sts:AssumeRole"}}`)
	res := roleResource(acct, "r", tr)
	want(t, ask(u, "sts:AssumeRole", res), ImplicitDeny)
	u.Identity = []Policy{identity(t, `{"Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}}`)}
	want(t, ask(u, "sts:AssumeRole", res), Allow)
}

// docs: reference_policies_elements_principal.html
func TestE18WildcardTrustRestrictedToOrganization(t *testing.T) {
	tr := trust(t, `{"Statement":{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole","Condition":{"StringEquals":{"aws:PrincipalOrgID":"`+ourOrg+`"}}}}`)
	res := roleResource(acct, "r", tr)
	insider := user(other, "inside", identity(t, `{"Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}}`))
	insider.OrgID = ourOrg
	want(t, ask(insider, "sts:AssumeRole", res), Allow)
	want(t, ask(&Principal{Kind: PrincipalExternal, Account: external}, "sts:AssumeRole", res), ImplicitDeny)
	want(t, ask(&Principal{Kind: PrincipalAnonymous}, "sts:AssumeRole", res), ImplicitDeny)
}

func TestE19WildcardTrustWithoutOrganizationDataIsConditional(t *testing.T) {
	tr := trust(t, `{"Statement":{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole","Condition":{"StringEquals":{"aws:PrincipalOrgID":"`+ourOrg+`"}}}}`)
	ext := &Principal{Kind: PrincipalExternal, Account: external}
	got := Evaluate(&Request{Principal: ext, Action: "sts:AssumeRole", Resource: roleResource(acct, "r", tr), Context: NewContext(ext, "")})
	want(t, got, Conditional)
	if strings.Join(got.Unevaluated, ",") != "aws:principalorgid" {
		t.Errorf("Unevaluated = %v", got.Unevaluated)
	}
}

func TestE20TrustWithDeletedPrincipalIDMatchesNothing(t *testing.T) {
	tr := trust(t, `{"Statement":{"Effect":"Allow","Principal":{"AWS":"AROADELETEDROLE00000"},"Action":"sts:AssumeRole"}}`)
	want(t, ask(role(acct, "caller"), "sts:AssumeRole", roleResource(acct, "r", tr)), ImplicitDeny)
	recreated := role(acct, "caller")
	recreated.ID = "AROADELETEDROLE00000"
	want(t, ask(recreated, "sts:AssumeRole", roleResource(acct, "r", tr)), Allow)
}

func TestE21PartialWildcardPrincipalMatchesNothing(t *testing.T) {
	tr := trust(t, `{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::`+acct+`:role/*"},"Action":"sts:AssumeRole"}}`)
	want(t, ask(role(acct, "caller"), "sts:AssumeRole", roleResource(acct, "r", tr)), ImplicitDeny)
}

// docs: reference_policies_elements_resource.html (E22–E26; the matcher has
// the full table in internal/match).
func TestE22ToE26WildcardsThroughTheEvaluator(t *testing.T) {
	pr := user(acct, "u", identity(t, `{"Statement":[
		{"Effect":"Allow","Action":"iam:*Policy*","Resource":"arn:aws:iam::*"},
		{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::example-bucket/*/test/*"}]}`))
	want(t, ask(pr, "IAM:putrolepolicy", onResource("arn:aws:iam::"+acct+":role/x", acct)), Allow)
	want(t, ask(pr, "iam:PassRole", onResource("arn:aws:iam::"+acct+":role/x", acct)), ImplicitDeny)
	want(t, ask(pr, "s3:GetObject", onResource("arn:aws:s3:::example-bucket/a/b/test/c", "")), Allow)
	want(t, ask(pr, "s3:GetObject", onResource("arn:aws:s3:::Example-bucket/a/test/c", "")), ImplicitDeny)
}

// docs: reference_policies_elements_condition_operators.html
func TestE27DenyWithUnevaluatedConditionMakesAllowConditional(t *testing.T) {
	pr := user(acct, "u", identity(t, `{"Statement":[
		{"Effect":"Allow","Action":"*","Resource":"*"},
		{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}}}]}`))
	got := ask(pr, "iam:CreateAccessKey", onResource("arn:aws:iam::"+acct+":user/u", acct))
	want(t, got, Conditional)
	if strings.Join(got.Unevaluated, ",") != "aws:multifactorauthpresent" {
		t.Errorf("Unevaluated = %v", got.Unevaluated)
	}
}

func TestE28IfExistsOnMissingKeyIsTrue(t *testing.T) {
	pr := user(acct, "u", identity(t, `{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"StringNotEqualsIfExists":{"iam:PassedToService":"ec2.amazonaws.com"}}}}`))
	want(t, ask(pr, "s3:GetObject", bucket), Allow)
}

// docs: reference_policies_condition-single-vs-multi-valued-context-keys.html
func TestE29ForAllValuesOnMissingKeyIsTrue(t *testing.T) {
	pr := user(acct, "u", identity(t, `{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"ForAllValues:StringEquals":{"iam:PassedToService":"ec2.amazonaws.com"}}}}`))
	want(t, ask(pr, "s3:GetObject", bucket), Allow)
}

func TestE30NegatedOperatorOnMissingKeyIsTrue(t *testing.T) {
	pr := user(acct, "u", identity(t, `{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"StringNotLike":{"iam:PassedToService":"*"}}}}`))
	want(t, ask(pr, "s3:GetObject", bucket), Allow)
}

// docs: reference_policies_elements_notprincipal.html — rejected by the
// parser, so it never reaches the evaluator.
func TestE31NotPrincipalWithAllowIsRejected(t *testing.T) {
	_, err := policy.Parse([]byte(`{"Statement":{"Effect":"Allow","NotPrincipal":{"AWS":"x"},"Action":"*"}}`), policy.KindResource, policy.Limits{})
	if err == nil {
		t.Fatal("NotPrincipal with Allow was accepted")
	}
}

// docs: id_roles_use_passrole.html
func TestE32PassedToServiceRestrictsPassRole(t *testing.T) {
	pr := user(acct, "u", identity(t, `{"Statement":{"Effect":"Allow","Action":"iam:PassRole","Resource":"*","Condition":{"StringEquals":{"iam:PassedToService":"ec2.amazonaws.com"}}}}`))
	target := onResource("arn:aws:iam::"+acct+":role/admin", acct)
	toLambda := Evaluate(&Request{Principal: pr, Action: "iam:PassRole", Resource: target, Context: WithPassedToService(NewContext(pr, ""), "lambda.amazonaws.com")})
	want(t, toLambda, ImplicitDeny)
	toEC2 := Evaluate(&Request{Principal: pr, Action: "iam:PassRole", Resource: target, Context: WithPassedToService(NewContext(pr, ""), "ec2.amazonaws.com")})
	want(t, toEC2, Allow)
}

func TestE33PassRoleOnlyInOwnAccount(t *testing.T) {
	pr := user(acct, "u", identity(t, allowAll))
	want(t, ask(pr, "iam:PassRole", onResource("arn:aws:iam::"+other+":role/admin", other)), ImplicitDeny)
}

// E34 and E35 concern parsing; they are tested in internal/snapshot and
// internal/policy.

// docs: orgs_manage_policies_scps_evaluation.html (E36, docs/research.md §5).
func TestE36SCPsNotCollectedMakeDecisionConditional(t *testing.T) {
	pr := user(acct, "u", identity(t, allowAll))
	pr.SCPsUnknown = true
	want(t, ask(pr, "iam:CreateAccessKey", onResource("arn:aws:iam::"+acct+":user/u", acct)), Conditional)
}

// docs: reference_policies_elements_principal.html ("All principals").
func TestE37WildcardTrustNeedsNoIdentityAndIgnoresBoundary(t *testing.T) {
	r := role(acct, "caller")
	r.Boundary = boundaryPolicy(t, `{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`)
	tr := trust(t, `{"Statement":{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}}`)
	want(t, ask(r, "sts:AssumeRole", roleResource(acct, "target", tr)), Allow)
}
