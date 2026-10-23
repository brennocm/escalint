package policy

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func mustParse(t *testing.T, kind Kind, doc string) *Document {
	t.Helper()
	d, err := Parse([]byte(doc), kind, Limits{})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	return d
}

func TestParseStatementShapes(t *testing.T) {
	t.Run("statement as object", func(t *testing.T) {
		d := mustParse(t, KindIdentity, `{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`)
		if len(d.Statements) != 1 || d.Statements[0].Index != 0 {
			t.Fatalf("got %+v", d.Statements)
		}
		if d.Version != "" {
			t.Errorf("Version = %q, want empty when absent", d.Version)
		}
	})
	t.Run("statement as list keeps order and index", func(t *testing.T) {
		d := mustParse(t, KindIdentity, `{"Version":"2012-10-17","Statement":[
			{"Sid":"A","Effect":"Allow","Action":"s3:*","Resource":"*"},
			{"Sid":"B","Effect":"Deny","Action":"s3:DeleteBucket","Resource":"*"}]}`)
		if got := []string{d.Statements[0].Sid, d.Statements[1].Sid}; !reflect.DeepEqual(got, []string{"A", "B"}) {
			t.Fatalf("Sids = %v", got)
		}
		if d.Statements[1].Index != 1 || d.Statements[1].Effect != Deny {
			t.Fatalf("second statement = %+v", d.Statements[1])
		}
	})
}

func TestParseStringListShapes(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want StringList
	}{
		{"action string", `{"Statement":{"Effect":"Allow","Action":"iam:PassRole","Resource":"*"}}`, StringList{"iam:PassRole"}},
		{"action list", `{"Statement":{"Effect":"Allow","Action":["iam:PassRole","IAM:getRole"],"Resource":"*"}}`, StringList{"iam:PassRole", "IAM:getRole"}},
		{"empty list", `{"Statement":{"Effect":"Allow","Action":[],"Resource":"*"}}`, StringList{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := mustParse(t, KindIdentity, tc.doc)
			if got := d.Statements[0].Action; !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Action = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestActionPatternsLowercaseAndKeepOriginal(t *testing.T) {
	d := mustParse(t, KindIdentity, `{"Statement":{"Effect":"Allow","NotAction":["IAM:Put*","S3:GetObject"],"Resource":"*"}}`)
	st := d.Statements[0]
	if got := st.ActionPatterns(); !reflect.DeepEqual(got, []string{"iam:put*", "s3:getobject"}) {
		t.Errorf("ActionPatterns() = %v", got)
	}
	if st.NotAction[0] != "IAM:Put*" {
		t.Errorf("original spelling lost: %v", st.NotAction)
	}
}

func TestParsePrincipalShapes(t *testing.T) {
	tests := []struct {
		name string
		elem string
		want Principal
	}{
		{"wildcard string", `"*"`, Principal{Wildcard: true}},
		{"aws wildcard", `{"AWS":"*"}`, Principal{AWS: StringList{"*"}}},
		{"account id", `{"AWS":"111111111111"}`, Principal{AWS: StringList{"111111111111"}}},
		{
			"aws list", `{"AWS":["arn:aws:iam::111111111111:root","arn:aws:iam::222222222222:role/x"]}`,
			Principal{AWS: StringList{"arn:aws:iam::111111111111:root", "arn:aws:iam::222222222222:role/x"}},
		},
		{
			"service", `{"Service":["ec2.amazonaws.com","lambda.amazonaws.com"]}`,
			Principal{Service: StringList{"ec2.amazonaws.com", "lambda.amazonaws.com"}},
		},
		{"federated", `{"Federated":"cognito-identity.amazonaws.com"}`, Principal{Federated: StringList{"cognito-identity.amazonaws.com"}}},
		{
			"canonical user", `{"CanonicalUser":"79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"}`,
			Principal{CanonicalUser: StringList{"79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"}},
		},
		{
			"mixed types", `{"Service":"ec2.amazonaws.com","AWS":"999999999999"}`,
			Principal{AWS: StringList{"999999999999"}, Service: StringList{"ec2.amazonaws.com"}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := mustParse(t, KindResource, `{"Statement":{"Effect":"Allow","Principal":`+tc.elem+`,"Action":"sts:AssumeRole"}}`)
			if got := *d.Statements[0].Principal; !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Principal = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestParseNotPrincipalWithDeny(t *testing.T) {
	d := mustParse(t, KindResource, `{"Statement":{"Effect":"Deny","NotPrincipal":{"AWS":"arn:aws:iam::111111111111:role/x"},"Action":"s3:*","Resource":"*"}}`)
	if d.Statements[0].NotPrincipal == nil || d.Statements[0].Principal != nil {
		t.Fatalf("got %+v", d.Statements[0])
	}
}

func TestParseCondition(t *testing.T) {
	d := mustParse(t, KindIdentity, `{"Statement":{"Effect":"Allow","Action":"iam:PassRole","Resource":"*","Condition":{
		"StringLike":{"aws:userid":"AIDA*","aws:PrincipalTag/team":["a","b"]},
		"Bool":{"aws:SecureTransport":true},
		"NumericLessThan":{"s3:max-keys":10},
		"ForAnyValue:StringEquals":{"aws:TagKeys":["env"]},
		"NullIfExists":{"aws:TokenIssueTime":"false"}}}}`)
	want := Condition{
		{Operator: "Bool", Key: "aws:SecureTransport", Values: []string{"true"}},
		{Operator: "ForAnyValue:StringEquals", Key: "aws:TagKeys", Values: []string{"env"}},
		{Operator: "NullIfExists", Key: "aws:TokenIssueTime", Values: []string{"false"}},
		{Operator: "NumericLessThan", Key: "s3:max-keys", Values: []string{"10"}},
		{Operator: "StringLike", Key: "aws:PrincipalTag/team", Values: []string{"a", "b"}},
		{Operator: "StringLike", Key: "aws:userid", Values: []string{"AIDA*"}},
	}
	if got := d.Statements[0].Condition; !reflect.DeepEqual(got, want) {
		t.Errorf("Condition =\n%+v\nwant\n%+v", got, want)
	}
	if !d.Statements[0].HasCondition() {
		t.Error("HasCondition() = false")
	}
}

func TestParseErrors(t *testing.T) {
	stmt := func(body string) string { return `{"Statement":{` + body + `}}` }
	tests := []struct {
		name     string
		kind     Kind
		doc      string
		wantPath string
		wantMsg  string
	}{
		{"invalid json", KindIdentity, `{"Statement":`, "Statement", "invalid JSON"},
		{"not an object", KindIdentity, `[1,2]`, "", "must be a JSON object"},
		{"trailing data", KindIdentity, `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}} {}`, "", "unexpected data"},
		{"empty", KindIdentity, ``, "", "invalid JSON"},
		{"missing statement", KindIdentity, `{"Version":"2012-10-17"}`, "", "missing Statement"},
		{"empty statement list", KindIdentity, `{"Statement":[]}`, "Statement", "at least one"},
		{"unknown top-level element", KindIdentity, `{"Statement":[],"Foo":1}`, "", `unknown element "Foo"`},
		{"case-insensitive key is not accepted", KindIdentity, stmt(`"effect":"Allow","Action":"*","Resource":"*"`), "Statement", `unknown element "effect"`},
		{"duplicate key", KindIdentity, stmt(`"Effect":"Deny","Effect":"Allow","Action":"*","Resource":"*"`), "Statement.Effect", "duplicate key"},
		{"duplicate key nested", KindIdentity, stmt(`"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Bool":{"k":true,"k":false}}`), "Statement.Condition.Bool.k", "duplicate key"},
		{"bad version", KindIdentity, `{"Version":"2024-01-01","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`, "Version", "unsupported version"},
		{"version not string", KindIdentity, `{"Version":1,"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`, "Version", "must be a string"},
		{"missing effect", KindIdentity, stmt(`"Action":"*","Resource":"*"`), "Statement", "missing Effect"},
		{"lowercase effect value", KindIdentity, stmt(`"Effect":"allow","Action":"*","Resource":"*"`), "Statement.Effect", `"Allow" or "Deny"`},
		{"action and notaction", KindIdentity, stmt(`"Effect":"Allow","Action":"*","NotAction":"iam:*","Resource":"*"`), "Statement", "exactly one of Action"},
		{"no action", KindIdentity, stmt(`"Effect":"Allow","Resource":"*"`), "Statement", "exactly one of Action"},
		{"action number", KindIdentity, stmt(`"Effect":"Allow","Action":5,"Resource":"*"`), "Statement.Action", "string or a list"},
		{"action list with number", KindIdentity, stmt(`"Effect":"Allow","Action":["a",5],"Resource":"*"`), "Statement.Action", "must be strings"},
		{"resource and notresource", KindIdentity, stmt(`"Effect":"Allow","Action":"*","Resource":"*","NotResource":"x"`), "Statement", "cannot both"},
		{"identity without resource", KindIdentity, stmt(`"Effect":"Allow","Action":"*"`), "Statement", "Resource and NotResource is required"},
		{"identity with principal", KindIdentity, stmt(`"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"`), "Statement", "cannot contain Principal"},
		{"trust without principal", KindResource, stmt(`"Effect":"Allow","Action":"sts:AssumeRole"`), "Statement", "require Principal"},
		{"principal and notprincipal", KindResource, stmt(`"Effect":"Deny","Principal":"*","NotPrincipal":"*","Action":"*"`), "Statement", "cannot both"},
		{"notprincipal with allow", KindResource, stmt(`"Effect":"Allow","NotPrincipal":{"AWS":"x"},"Action":"*"`), "Statement.NotPrincipal", "only supported with Deny"},
		{"notprincipal in scp", KindSCP, stmt(`"Effect":"Deny","NotPrincipal":{"AWS":"x"},"Action":"*","Resource":"*"`), "Statement", "not supported in SCP"},
		{"principal bad string", KindResource, stmt(`"Effect":"Allow","Principal":"AWS","Action":"*"`), "Statement.Principal", `must be "*"`},
		{"principal unknown type", KindResource, stmt(`"Effect":"Allow","Principal":{"Group":"x"},"Action":"*"`), "Statement.Principal", "unknown principal type"},
		{"principal empty object", KindResource, stmt(`"Effect":"Allow","Principal":{},"Action":"*"`), "Statement.Principal", "at least one"},
		{"principal number", KindResource, stmt(`"Effect":"Allow","Principal":3,"Action":"*"`), "Statement.Principal", `must be "*" or an object`},
		{"condition not object", KindIdentity, stmt(`"Effect":"Allow","Action":"*","Resource":"*","Condition":"x"`), "Statement.Condition", "object of condition operators"},
		{"condition operator not object", KindIdentity, stmt(`"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Bool":true}`), "Statement.Condition", "object of condition keys"},
		{"condition empty keys", KindIdentity, stmt(`"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Bool":{}}`), "Statement.Condition", "at least one condition key"},
		{"condition nested object", KindIdentity, stmt(`"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Bool":{"k":{"x":1}}}`), "Statement.Condition", "strings, booleans or numbers"},
		{"condition null", KindIdentity, stmt(`"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Bool":{"k":null}}`), "Statement.Condition", "null"},
		{"condition list with object", KindIdentity, stmt(`"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Bool":{"k":[{}]}}`), "Statement.Condition", "strings, booleans or numbers"},
		{"sid not string", KindIdentity, stmt(`"Sid":1,"Effect":"Allow","Action":"*","Resource":"*"`), "Statement.Sid", "must be a string"},
		{"statement not object", KindIdentity, `{"Statement":[1]}`, "Statement[0]", "must be an object"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.doc), tc.kind, Limits{})
			var pe *ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("Parse() error = %v, want *ParseError", err)
			}
			if pe.Path != tc.wantPath {
				t.Errorf("Path = %q, want %q (error: %v)", pe.Path, tc.wantPath, err)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantMsg)
			}
		})
	}
}

func TestParseLimits(t *testing.T) {
	deep := strings.Repeat(`{"a":`, 30) + `1` + strings.Repeat(`}`, 30)
	manyStatements := `{"Statement":[` + strings.TrimSuffix(strings.Repeat(`{"Effect":"Allow","Action":"*","Resource":"*"},`, 3), ",") + `]}`
	manyValues := `{"Statement":{"Effect":"Allow","Action":[` + strings.TrimSuffix(strings.Repeat(`"a",`, 50), ",") + `],"Resource":"*"}}`
	tests := []struct {
		name   string
		doc    string
		limits Limits
	}{
		{"bytes", `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`, Limits{MaxBytes: 10}},
		{"depth", deep, Limits{}},
		{"statements", manyStatements, Limits{MaxStatements: 2}},
		{"values", manyValues, Limits{MaxValues: 20}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.doc), KindIdentity, tc.limits)
			if !errors.Is(err, ErrLimitExceeded) {
				t.Fatalf("Parse() error = %v, want ErrLimitExceeded", err)
			}
		})
	}
}

func TestParseTestdata(t *testing.T) {
	files := map[string]Kind{
		"admin.json":              KindIdentity,
		"trust-github-oidc.json":  KindResource,
		"notaction-deny-mfa.json": KindIdentity,
		"passrole-scoped.json":    KindIdentity,
	}
	for name, kind := range files {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", name))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Parse(data, kind, Limits{}); err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
		})
	}
}

func TestKindString(t *testing.T) {
	for kind, want := range map[Kind]string{KindIdentity: "identity", KindResource: "resource", KindSCP: "scp", KindRCP: "rcp", Kind(9): "Kind(9)"} {
		if got := kind.String(); got != want {
			t.Errorf("Kind(%d).String() = %q, want %q", int(kind), got, want)
		}
	}
}

func TestParseErrorFormat(t *testing.T) {
	inner := errors.New("boom")
	err := &ParseError{Msg: "bad", Err: inner}
	if err.Error() != "policy: bad" || !errors.Is(err, inner) {
		t.Errorf("unexpected %q", err.Error())
	}
}
