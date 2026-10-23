package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Principal is the Principal or NotPrincipal element of a resource-based
// policy (in v1, a role trust policy).
//
// "Principal": "*" sets Wildcard. The map form fills the typed lists; AWS
// treats {"AWS": "*"} like "*" for AWS principals, which the evaluator
// handles, so both forms are kept as written.
type Principal struct {
	Wildcard      bool
	AWS           StringList
	Service       StringList
	Federated     StringList
	CanonicalUser StringList
}

// principalTypes lists the keys AWS documents for the map form.
var principalTypes = []string{"AWS", "CanonicalUser", "Federated", "Service"}

// UnmarshalJSON accepts "*" or an object whose keys are principal types.
func (p *Principal) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(trimmed, &s); err != nil {
			return err
		}
		if s != "*" {
			return fmt.Errorf("string form must be \"*\", got %q", s)
		}
		*p = Principal{Wildcard: true}
		return nil
	}
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return errors.New(`must be "*" or an object of principal types`)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	if len(raw) == 0 {
		return errors.New("object must name at least one principal type")
	}
	var out Principal
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		var list StringList
		if err := json.Unmarshal(raw[k], &list); err != nil {
			return fmt.Errorf("%s: %w", strconv.Quote(k), err)
		}
		switch k {
		case "AWS":
			out.AWS = list
		case "Service":
			out.Service = list
		case "Federated":
			out.Federated = list
		case "CanonicalUser":
			out.CanonicalUser = list
		default:
			return fmt.Errorf("unknown principal type %q (expected one of %s)", k, strings.Join(principalTypes, ", "))
		}
	}
	*p = out
	return nil
}

// Count returns how many principal strings the element holds.
func (p *Principal) Count() int {
	if p == nil {
		return 0
	}
	n := len(p.AWS) + len(p.Service) + len(p.Federated) + len(p.CanonicalUser)
	if p.Wildcard {
		n++
	}
	return n
}
