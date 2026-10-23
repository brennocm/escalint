package eval

import (
	"reflect"
	"testing"

	"github.com/brennocm/escalint/internal/policy"
)

// FuzzEvaluate feeds arbitrary identity and trust policies to the evaluator:
// it must never panic, must be deterministic and must keep decisions in
// range.
func FuzzEvaluate(f *testing.F) {
	f.Add([]byte(allowAll), []byte(`{"Statement":{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}}`))
	f.Add([]byte(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::${aws:username}/*"}}`),
		[]byte(`{"Statement":{"Effect":"Deny","NotPrincipal":{"AWS":"111111111111"},"Action":"*","Condition":{"ForAllValues:StringLike":{"aws:PrincipalArn":["*"]}}}}`))
	f.Fuzz(func(t *testing.T, identityDoc, trustDoc []byte) {
		id, err := policy.Parse(identityDoc, policy.KindIdentity, policy.Limits{})
		if err != nil {
			return
		}
		pr := &Principal{Kind: PrincipalUser, ARN: "arn:aws:iam::111111111111:user/u", Account: "111111111111", Identity: []Policy{{Type: TypeIdentity, Source: "fuzz", Doc: id}}}
		res := &Resource{ARN: "arn:aws:iam::111111111111:role/r", Account: "111111111111"}
		if tr, err := policy.Parse(trustDoc, policy.KindResource, policy.Limits{}); err == nil {
			res.Policy = &Policy{Type: TypeResource, Source: "fuzz-trust", Doc: tr}
		}
		for _, action := range []string{"sts:AssumeRole", "iam:PassRole", "s3:GetObject"} {
			req := &Request{Principal: pr, Action: action, Resource: res, Context: NewContext(pr, "o-fuzz")}
			a, b := Evaluate(req), Evaluate(req)
			if !reflect.DeepEqual(a, b) {
				t.Fatal("not deterministic")
			}
			if a.Decision < ExplicitDeny || a.Decision > Allow {
				t.Fatalf("decision out of range: %d", a.Decision)
			}
		}
	})
}
