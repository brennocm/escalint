package policy

import (
	"bytes"
	"encoding/json"
	"errors"
)

// StringList is an element that AWS accepts either as a single string or as
// a list of strings, such as Action, Resource or a principal list. The order
// of the document is preserved for display.
type StringList []string

// UnmarshalJSON accepts "x" and ["x", "y"]. Anything else is an error,
// including an empty list: "NotAction": [] would mean "every action", which
// is too easy to misread as "no action", so it is rejected and reported.
func (s *StringList) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '"' {
		var one string
		if err := json.Unmarshal(trimmed, &one); err != nil {
			return err
		}
		*s = StringList{one}
		return nil
	}
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var raw []json.RawMessage
		if err := json.Unmarshal(trimmed, &raw); err != nil {
			return err
		}
		if len(raw) == 0 {
			return errors.New("list must not be empty")
		}
		out := make(StringList, 0, len(raw))
		for _, item := range raw {
			var v string
			if err := json.Unmarshal(item, &v); err != nil {
				return errors.New("list items must be strings")
			}
			out = append(out, v)
		}
		*s = out
		return nil
	}
	return errors.New("must be a string or a list of strings")
}
