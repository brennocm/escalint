package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/brennocm/escalint/internal/jsonx"
)

// Effect is "Allow" or "Deny", matched exactly as AWS documents it.
type Effect string

// Effects.
const (
	Allow Effect = "Allow"
	Deny  Effect = "Deny"
)

// Kind selects which elements a document may contain.
type Kind int

// Policy kinds. Permissions boundaries use KindIdentity rules; v1 only
// parses role trust policies as KindResource.
const (
	KindIdentity Kind = iota // identity-based policies and permissions boundaries
	KindResource             // resource-based policies, including role trust policies
	KindSCP                  // AWS Organizations service control policies
	KindRCP                  // AWS Organizations resource control policies
)

func (k Kind) String() string {
	switch k {
	case KindIdentity:
		return "identity"
	case KindResource:
		return "resource"
	case KindSCP:
		return "scp"
	case KindRCP:
		return "rcp"
	default:
		return fmt.Sprintf("Kind(%d)", int(k))
	}
}

// Versions accepted in the Version element ("" means absent; policy
// variables are then treated as literal text by the evaluator).
const (
	Version2012 = "2012-10-17"
	Version2008 = "2008-10-17"
)

// Document is a parsed policy.
type Document struct {
	Version    string
	ID         string
	Statements []Statement
}

// Statement is one entry of the Statement element. Exactly one of Action and
// NotAction is set; for identity policies exactly one of Resource and
// NotResource is set. Values keep the spelling of the document.
type Statement struct {
	Index        int // position in the document, for evidence and display
	Sid          string
	Effect       Effect
	Principal    *Principal
	NotPrincipal *Principal
	Action       StringList
	NotAction    StringList
	Resource     StringList
	NotResource  StringList
	Condition    Condition
}

// HasCondition reports whether the statement has any condition clause.
func (s *Statement) HasCondition() bool {
	return len(s.Condition) > 0
}

// ActionPatterns returns the Action or NotAction patterns in lower case and
// whether they come from NotAction (negated). Action names are
// case-insensitive in IAM; the original spelling stays in Action/NotAction
// for display. The choice depends on which element is present, never on list
// length, so a statement can never be misread as the opposite element.
func (s *Statement) ActionPatterns() (patterns []string, negated bool) {
	src := s.Action
	if s.NotAction != nil {
		src, negated = s.NotAction, true
	}
	patterns = make([]string, len(src))
	for i, a := range src {
		patterns[i] = strings.ToLower(a)
	}
	return patterns, negated
}

// Parse parses a policy document of the given kind. The zero Limits value
// means DefaultLimits. Every failure is a *ParseError.
func Parse(data []byte, kind Kind, limits Limits) (*Document, error) {
	limits = limits.withDefaults()
	if len(data) > limits.MaxBytes {
		return nil, &ParseError{
			Msg: fmt.Sprintf("document is %d bytes, limit is %d", len(data), limits.MaxBytes),
			Err: ErrLimitExceeded,
		}
	}
	if err := jsonx.Check(data, limits.MaxDepth); err != nil {
		var se *jsonx.Error
		if errors.As(err, &se) {
			pe := &ParseError{Path: se.Path, Msg: se.Msg, Err: se.Err}
			if errors.Is(err, jsonx.ErrTooDeep) {
				pe.Err = ErrLimitExceeded
			}
			return nil, pe
		}
		return nil, &ParseError{Msg: "invalid JSON", Err: err}
	}

	top, err := objectMembers(data)
	if err != nil {
		return nil, &ParseError{Msg: "document must be a JSON object", Err: err}
	}
	if err := onlyKeys(top, "", "Version", "Id", "Statement"); err != nil {
		return nil, err
	}

	doc := &Document{}
	if raw, ok := top["Version"]; ok {
		if err := decodeString(raw, &doc.Version); err != nil {
			return nil, errorf("Version", "must be a string")
		}
		if doc.Version != Version2012 && doc.Version != Version2008 {
			return nil, errorf("Version", "unsupported version %q", doc.Version)
		}
	}
	if raw, ok := top["Id"]; ok {
		if err := decodeString(raw, &doc.ID); err != nil {
			return nil, errorf("Id", "must be a string")
		}
	}
	rawStatements, ok := top["Statement"]
	if !ok {
		return nil, errorf("", "missing Statement")
	}
	items, err := statementItems(rawStatements)
	if err != nil {
		return nil, err
	}
	if len(items) > limits.MaxStatements {
		return nil, &ParseError{
			Path: "Statement",
			Msg:  fmt.Sprintf("%d statements, limit is %d", len(items), limits.MaxStatements),
			Err:  ErrLimitExceeded,
		}
	}

	values := 0
	for i, item := range items {
		path := fmt.Sprintf("Statement[%d]", i)
		if len(items) == 1 && !isArray(rawStatements) {
			path = "Statement"
		}
		st, err := parseStatement(item, path, kind)
		if err != nil {
			return nil, err
		}
		st.Index = i
		values += len(st.Action) + len(st.NotAction) + len(st.Resource) + len(st.NotResource) +
			st.Principal.Count() + st.NotPrincipal.Count()
		for _, c := range st.Condition {
			values += len(c.Values)
		}
		if values > limits.MaxValues {
			return nil, &ParseError{
				Path: path,
				Msg:  fmt.Sprintf("more than %d values in the document", limits.MaxValues),
				Err:  ErrLimitExceeded,
			}
		}
		doc.Statements = append(doc.Statements, st)
	}
	return doc, nil
}

var statementKeys = []string{
	"Sid", "Effect", "Principal", "NotPrincipal", "Action", "NotAction",
	"Resource", "NotResource", "Condition",
}

func parseStatement(data json.RawMessage, path string, kind Kind) (Statement, error) {
	var st Statement
	raw, err := objectMembers(data)
	if err != nil {
		return st, errorf(path, "statement must be an object")
	}
	if err := onlyKeys(raw, path, statementKeys...); err != nil {
		return st, err
	}

	if v, ok := raw["Sid"]; ok {
		if err := decodeString(v, &st.Sid); err != nil {
			return st, errorf(jsonx.JoinPath(path, "Sid"), "must be a string")
		}
	}
	rawEffect, ok := raw["Effect"]
	if !ok {
		return st, errorf(path, "missing Effect")
	}
	var effect string
	if err := decodeString(rawEffect, &effect); err != nil {
		return st, errorf(jsonx.JoinPath(path, "Effect"), "must be a string")
	}
	st.Effect = Effect(effect)
	if st.Effect != Allow && st.Effect != Deny {
		return st, errorf(jsonx.JoinPath(path, "Effect"), `must be "Allow" or "Deny", got %q`, effect)
	}

	fields := []struct {
		name string
		dst  *StringList
	}{
		{"Action", &st.Action},
		{"NotAction", &st.NotAction},
		{"Resource", &st.Resource},
		{"NotResource", &st.NotResource},
	}
	for _, f := range fields {
		if v, ok := raw[f.name]; ok {
			if err := json.Unmarshal(v, f.dst); err != nil {
				return st, errorf(jsonx.JoinPath(path, f.name), "%v", err)
			}
		}
	}
	for _, f := range []struct {
		name string
		dst  **Principal
	}{{"Principal", &st.Principal}, {"NotPrincipal", &st.NotPrincipal}} {
		if v, ok := raw[f.name]; ok {
			p := &Principal{}
			if err := json.Unmarshal(v, p); err != nil {
				return st, errorf(jsonx.JoinPath(path, f.name), "%v", err)
			}
			*f.dst = p
		}
	}
	if v, ok := raw["Condition"]; ok {
		if err := json.Unmarshal(v, &st.Condition); err != nil {
			return st, errorf(jsonx.JoinPath(path, "Condition"), "%v", err)
		}
	}

	return st, validateStatement(&st, raw, path, kind)
}

// validateStatement applies the element rules documented by AWS (see
// docs/research.md §2.4 and §2.6).
func validateStatement(st *Statement, raw map[string]json.RawMessage, path string, kind Kind) error {
	has := func(k string) bool { _, ok := raw[k]; return ok }

	if has("Action") == has("NotAction") {
		return errorf(path, "exactly one of Action and NotAction is required")
	}
	if has("Resource") && has("NotResource") {
		return errorf(path, "Resource and NotResource cannot both be present")
	}
	if has("Principal") && has("NotPrincipal") {
		return errorf(path, "Principal and NotPrincipal cannot both be present")
	}
	if has("NotPrincipal") && st.Effect != Deny {
		return errorf(jsonx.JoinPath(path, "NotPrincipal"), "NotPrincipal is only supported with Deny")
	}

	switch kind {
	case KindIdentity:
		if has("Principal") || has("NotPrincipal") {
			return errorf(path, "identity-based policies cannot contain Principal or NotPrincipal")
		}
		if !has("Resource") && !has("NotResource") {
			return errorf(path, "one of Resource and NotResource is required")
		}
	case KindResource:
		if !has("Principal") && !has("NotPrincipal") {
			return errorf(path, "resource-based policies require Principal or NotPrincipal")
		}
	case KindSCP, KindRCP:
		if has("NotPrincipal") {
			return errorf(path, "NotPrincipal is not supported in %s policies", strings.ToUpper(kind.String()))
		}
	}
	return nil
}

// decodeString decodes a JSON string and rejects null, which json.Unmarshal
// would accept as "leave the field empty".
func decodeString(raw json.RawMessage, dst *string) error {
	if isNull(raw) {
		return errors.New("null")
	}
	return json.Unmarshal(raw, dst)
}

func statementItems(raw json.RawMessage) ([]json.RawMessage, error) {
	if isNull(raw) {
		return nil, errorf("Statement", "must be an object or a list of objects")
	}
	if isArray(raw) {
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, errorf("Statement", "must be an object or a list of objects")
		}
		if len(items) == 0 {
			return nil, errorf("Statement", "must contain at least one statement")
		}
		return items, nil
	}
	return []json.RawMessage{raw}, nil
}

func isArray(raw json.RawMessage) bool {
	for _, b := range raw {
		switch b {
		case ' ', '\t', '\n', '\r':
			continue
		case '[':
			return true
		default:
			return false
		}
	}
	return false
}

// onlyKeys rejects any key not in allowed. Keys are compared exactly.
func onlyKeys(m map[string]json.RawMessage, path string, allowed ...string) error {
	var unknown []string
	for k := range m {
		ok := false
		for _, a := range allowed {
			if k == a {
				ok = true
				break
			}
		}
		if !ok {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)
	return errorf(path, "unknown element %q", unknown[0])
}
