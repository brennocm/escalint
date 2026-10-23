package collect

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/brennocm/escalint/internal/catalog"
)

// servicePrefix maps each client interface to its IAM service prefix.
var servicePrefix = map[string]string{
	"STSAPI": "sts", "IAMAPI": "iam", "OrganizationsAPI": "organizations", "LambdaAPI": "lambda",
	"EC2API": "ec2", "SSMAPI": "ssm", "CodeBuildAPI": "codebuild",
}

// noPermission lists operations that need no IAM permission.
var noPermission = map[string]bool{"sts:GetCallerIdentity": true}

var readOnly = regexp.MustCompile(`^(List|Get|Describe|BatchGet)[A-Z]|^AssumeRole$`)

// usedActions extracts the operations of the client interfaces in api.go.
func usedActions(t *testing.T) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "api.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		it, ok := ts.Type.(*ast.InterfaceType)
		if !ok {
			return false
		}
		prefix, ok := servicePrefix[ts.Name.Name]
		if !ok {
			t.Errorf("interface %s has no service prefix", ts.Name.Name)
			return false
		}
		for _, m := range it.Methods.List {
			for _, name := range m.Names {
				if !readOnly.MatchString(name.Name) {
					t.Errorf("%s.%s is not a read-only operation", ts.Name.Name, name.Name)
				}
				if a := prefix + ":" + name.Name; !noPermission[a] {
					out = append(out, a)
				}
			}
		}
		return false
	})
	sort.Strings(out)
	return out
}

// The documented policy grants exactly the operations the collector calls.
func TestCollectorPolicyMatchesCode(t *testing.T) {
	raw, err := os.ReadFile("../../docs/collector-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Statement []struct {
			Action []string
		}
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var granted []string
	for _, st := range doc.Statement {
		granted = append(granted, st.Action...)
	}
	sort.Strings(granted)
	used := usedActions(t)
	if strings.Join(granted, ",") != strings.Join(used, ",") {
		t.Errorf("docs/collector-policy.json grants\n  %v\nbut the collector calls\n  %v", granted, used)
	}
	cat, err := catalog.Default()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range granted {
		if _, ok := cat.Lookup(a); !ok {
			t.Errorf("%s is not in the AWS action catalog", a)
		}
	}
}
