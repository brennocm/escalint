package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
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
func (c *Condition) UnmarshalJSON(data []byte) error {
	var ops map[string]json.RawMessage
	if err := json.Unmarshal(data, &ops); err != nil {
		return errors.New("must be an object of condition operators")
	}
	var out Condition
	for op, rawKeys := range ops {
		var keys map[string]json.RawMessage
		if err := json.Unmarshal(rawKeys, &keys); err != nil {
			return fmt.Errorf("%s: must be an object of condition keys", op)
		}
		if len(keys) == 0 {
			return fmt.Errorf("%s: must name at least one condition key", op)
		}
		for key, rawValues := range keys {
			values, err := conditionValues(rawValues)
			if err != nil {
				return fmt.Errorf("%s.%s: %w", op, key, err)
			}
			out = append(out, Clause{Operator: op, Key: key, Values: values})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Operator != out[j].Operator {
			return out[i].Operator < out[j].Operator
		}
		return out[i].Key < out[j].Key
	})
	*c = out
	return nil
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
