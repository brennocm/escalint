package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
)

// Clause is one operator/key pair of a Condition block, for example
// StringEquals / aws:PrincipalOrgID / ["o-123"].
type Clause struct {
	Operator string // as written, e.g. "ForAnyValue:StringLike"
	Key      string // as written; AWS compares keys case-insensitively
	Values   []string
}

// Condition is the Condition element. Clauses are sorted by operator then
// key so the model is deterministic regardless of JSON object order. AWS
// combines all clauses with AND and the values of one clause with OR.
type Condition []Clause

// UnmarshalJSON accepts {"Operator": {"key": value}} where value is a string,
// boolean, number or a list of them. Booleans and numbers keep their JSON
// text ("true", "10") because operators compare them as strings first.
//
// JSON null is rejected: treating "Condition": null as "no condition" would
// turn a conditional statement into an unconditional one. Operators and keys
// are visited in sorted order so the first error reported is deterministic.
func (c *Condition) UnmarshalJSON(data []byte) error {
	ops, err := objectMembers(data)
	if err != nil {
		return errors.New("must be an object of condition operators")
	}
	var out Condition
	for _, op := range sortedKeys(ops) {
		keys, err := objectMembers(ops[op])
		if err != nil {
			return fmt.Errorf("%s: must be an object of condition keys", strconv.Quote(op))
		}
		if len(keys) == 0 {
			return fmt.Errorf("%s: must name at least one condition key", strconv.Quote(op))
		}
		for _, key := range sortedKeys(keys) {
			values, err := conditionValues(keys[key])
			if err != nil {
				return fmt.Errorf("%s.%s: %w", strconv.Quote(op), strconv.Quote(key), err)
			}
			out = append(out, Clause{Operator: op, Key: key, Values: values})
		}
	}
	*c = out
	return nil
}

// objectMembers decodes a JSON object and rejects null, which
// json.Unmarshal would silently turn into a nil map.
func objectMembers(data []byte) (map[string]json.RawMessage, error) {
	if isNull(data) {
		return nil, errors.New("null")
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func sortedKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func isNull(data []byte) bool {
	return bytes.Equal(bytes.TrimSpace(data), []byte("null"))
}

func conditionValues(data []byte) ([]string, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var items []json.RawMessage
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return nil, err
		}
		values := make([]string, 0, len(items))
		for _, item := range items {
			v, err := scalarText(item)
			if err != nil {
				return nil, err
			}
			values = append(values, v)
		}
		return values, nil
	}
	v, err := scalarText(trimmed)
	if err != nil {
		return nil, err
	}
	return []string{v}, nil
}

// scalarText returns the value of a JSON string, or the literal text of a
// boolean or number. Objects, arrays and null are rejected.
func scalarText(data []byte) (string, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return "", errors.New("empty value")
	}
	switch trimmed[0] {
	case '"':
		var s string
		if err := json.Unmarshal(trimmed, &s); err != nil {
			return "", err
		}
		return s, nil
	case 't', 'f':
		var b bool
		if err := json.Unmarshal(trimmed, &b); err != nil {
			return "", err
		}
		if b {
			return "true", nil
		}
		return "false", nil
	case '{', '[':
		return "", errors.New("values must be strings, booleans or numbers")
	case 'n':
		return "", errors.New("null is not a valid condition value")
	default:
		var n json.Number
		if err := json.Unmarshal(trimmed, &n); err != nil {
			return "", errors.New("values must be strings, booleans or numbers")
		}
		return n.String(), nil
	}
}
