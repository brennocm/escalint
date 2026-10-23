package eval

import (
	"sort"
	"strings"

	"github.com/brennocm/escalint/internal/match"
	"github.com/brennocm/escalint/internal/policy"
)

// evaluatedKeys are the condition keys whose values are known statically
// (docs/research.md §2.7). Any other key makes a statement Conditional.
// aws:username and aws:userid are fixed by the snapshot for IAM users, like
// aws:PrincipalArn, and are also needed for policy variables.
var evaluatedKeys = map[string]bool{
	"aws:principalarn":          true,
	"aws:principalaccount":      true,
	"aws:principalorgid":        true,
	"aws:principalisawsservice": true,
	"iam:passedtoservice":       true,
	"aws:username":              true,
	"aws:userid":                true,
}

// tri is a three-valued truth value.
type tri int

const (
	triFalse tri = iota
	triUnknown
	triTrue
)

// and combines two tri values: false dominates, then unknown.
func and(a, b tri) tri {
	if a < b {
		return a
	}
	return b
}

// conditionResult is the value of a whole Condition element and the keys
// that could not be evaluated.
type conditionResult struct {
	value tri
	keys  []string
}

type operator struct {
	kind       string // "string", "arn", "bool", "null"
	negated    bool
	ignoreCase bool
	like       bool
}

var operators = map[string]operator{
	"StringEquals":              {kind: "string"},
	"StringNotEquals":           {kind: "string", negated: true},
	"StringEqualsIgnoreCase":    {kind: "string", ignoreCase: true},
	"StringNotEqualsIgnoreCase": {kind: "string", negated: true, ignoreCase: true},
	"StringLike":                {kind: "string", like: true},
	"StringNotLike":             {kind: "string", negated: true, like: true},
	"ArnEquals":                 {kind: "arn"},
	"ArnLike":                   {kind: "arn"},
	"ArnNotEquals":              {kind: "arn", negated: true},
	"ArnNotLike":                {kind: "arn", negated: true},
	"Bool":                      {kind: "bool"},
	"Null":                      {kind: "null"},
}

// evalCondition applies AND across clauses (docs: multiple keys and
// operators are ANDed; the values of one key are ORed).
func evalCondition(cond policy.Condition, ctx map[string][]string, version string) conditionResult {
	res := conditionResult{value: triTrue}
	unknown := map[string]bool{}
	for _, c := range cond {
		v, keys := evalClause(c, ctx, version)
		res.value = and(res.value, v)
		for _, k := range keys {
			unknown[k] = true
		}
	}
	if res.value == triUnknown {
		res.keys = sortedSet(unknown)
	}
	return res
}

func evalClause(c policy.Clause, ctx map[string][]string, version string) (tri, []string) {
	key := strings.ToLower(c.Key) // condition key names are case-insensitive
	opName, set := c.Operator, ""
	for _, prefix := range []string{"ForAnyValue:", "ForAllValues:"} {
		if strings.HasPrefix(opName, prefix) {
			set, opName = strings.TrimSuffix(prefix, ":"), strings.TrimPrefix(opName, prefix)
		}
	}
	ifExists := strings.HasSuffix(opName, "IfExists") && opName != "IfExists"
	if ifExists {
		opName = strings.TrimSuffix(opName, "IfExists")
	}
	op, supported := operators[opName]
	if !supported || (op.kind == "null" && (ifExists || set != "")) {
		// Numeric, Date, IpAddress, Binary… are not evaluated in v1.
		return triUnknown, []string{key}
	}
	if !evaluatedKeys[key] {
		return triUnknown, []string{key}
	}
	ctxValues, known := ctx[key]
	if !known {
		if key == "aws:principalorgid" {
			if v, ok := orgIDExcluded(op, set, ifExists, c.Values, ctx); ok {
				return v, nil
			}
		}
		return triUnknown, []string{key}
	}

	policyValues := make([]string, 0, len(c.Values))
	var variableKeys []string
	for _, v := range c.Values {
		s, missing := substitute(v, ctx, version)
		if len(missing) > 0 {
			variableKeys = append(variableKeys, missing...)
			continue
		}
		policyValues = append(policyValues, s)
	}
	if len(variableKeys) > 0 {
		return triUnknown, variableKeys
	}

	present := len(ctxValues) > 0
	if op.kind == "null" {
		for _, pv := range policyValues {
			if (strings.EqualFold(pv, "true") && !present) || (strings.EqualFold(pv, "false") && present) {
				return triTrue, nil
			}
		}
		return triFalse, nil
	}
	if !present {
		switch {
		case ifExists:
			return triTrue, nil
		case set == "ForAllValues":
			return triTrue, nil // documented: true when the key is missing
		case set == "ForAnyValue":
			return triFalse, nil
		case op.negated:
			return triTrue, nil
		default:
			return triFalse, nil
		}
	}

	matchesAny := func(cv string) bool {
		for _, pv := range policyValues {
			if valueMatches(op, pv, cv) {
				return true
			}
		}
		return false
	}
	var ok bool
	switch set {
	case "ForAllValues":
		ok = true
		for _, cv := range ctxValues {
			if matchesAny(cv) == op.negated {
				ok = false
				break
			}
		}
	default: // single-valued keys and ForAnyValue
		ok = false
		for _, cv := range ctxValues {
			if matchesAny(cv) != op.negated {
				ok = true
				break
			}
		}
	}
	if ok {
		return triTrue, nil
	}
	return triFalse, nil
}

// orgIDExcluded decides aws:PrincipalOrgID equality checks for a principal
// whose organization is unknown but known to differ from ours: comparing
// only against our organization ID gives a definite answer.
func orgIDExcluded(op operator, set string, ifExists bool, values []string, ctx map[string][]string) (tri, bool) {
	excluded := ctx[orgIDNotKey]
	if len(excluded) != 1 || op.kind != "string" || op.like || set != "" || ifExists || len(values) == 0 {
		return triUnknown, false
	}
	for _, v := range values {
		if !strings.EqualFold(v, excluded[0]) {
			return triUnknown, false
		}
	}
	if op.negated {
		return triTrue, true
	}
	return triFalse, true
}

func valueMatches(op operator, pattern, value string) bool {
	switch op.kind {
	case "arn":
		return match.ARN(pattern, value)
	case "bool":
		return strings.EqualFold(pattern, value)
	}
	switch {
	case op.like:
		return match.Glob(pattern, value)
	case op.ignoreCase:
		return strings.EqualFold(pattern, value)
	default:
		return pattern == value
	}
}

// substitute replaces policy variables (${aws:username}, ${*}, ${?}, ${$})
// in s. Variables only exist in Version 2012-10-17 documents; in older or
// unversioned documents the text is literal. It returns the condition keys
// of variables whose value is not known.
func substitute(s string, ctx map[string][]string, version string) (string, []string) {
	if version != policy.Version2012 || !strings.Contains(s, "${") {
		return s, nil
	}
	var b strings.Builder
	var missing []string
	for {
		start := strings.Index(s, "${")
		if start < 0 {
			b.WriteString(s)
			break
		}
		end := strings.IndexByte(s[start:], '}')
		if end < 0 {
			b.WriteString(s)
			break
		}
		b.WriteString(s[:start])
		name := strings.TrimSpace(s[start+2 : start+end])
		s = s[start+end+1:]
		switch name {
		case "*", "?", "$":
			b.WriteString(name)
			continue
		}
		key, def, hasDefault := strings.Cut(name, ",")
		key = strings.ToLower(strings.TrimSpace(key))
		values, known := ctx[key]
		switch {
		case known && len(values) == 1:
			b.WriteString(values[0])
		case known && len(values) == 0 && hasDefault:
			b.WriteString(strings.Trim(strings.TrimSpace(def), "'"))
		default:
			missing = append(missing, key)
		}
	}
	return b.String(), missing
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
