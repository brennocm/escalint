package policy

import (
	"strings"
	"testing"
)

func TestCanonicalJSONRoundTrip(t *testing.T) {
	src := `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"iam:PassRole","Resource":"*","Sid":"P"},
	{"Effect":"Deny","Principal":"*","NotAction":["s3:*"],"NotResource":"arn:aws:s3:::x","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-1"}}},
	{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"},
	{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com","AWS":["111111111111"]},"Action":"sts:AssumeRole"}],"Version":"2012-10-17","Id":"x"}`
	doc, err := Parse([]byte(src), KindResource, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	out, err := doc.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.HasPrefix(s, `{"Version":"2012-10-17","Id":"x","Statement":[{"Sid":"P","Effect":"Allow","Principal":"*","Action":["iam:PassRole"]`) {
		t.Errorf("order: %s", s)
	}
	for _, want := range []string{`"Principal":"*"`, `"Principal":{"AWS":["111111111111"],"Service":["lambda.amazonaws.com"]}`, `"Condition":{"StringEquals":{"aws:PrincipalOrgID":["o-1"]}}`, `"NotResource":["arn:aws:s3:::x"]`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in %s", want, s)
		}
	}
	again, err := Parse(out, KindResource, Limits{})
	if err != nil || len(again.Statements) != 4 {
		t.Fatalf("canonical JSON does not parse back: %v", err)
	}
}
